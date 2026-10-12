import re, sys
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as web
from accounts import User, db, get_keys, password_hash, save_keys

@pytest.fixture()
def application():
    a=web.app
    a.config.update(TESTING=True, SECRET_KEY='test-only', API_KEYS_ENCRYPTION_KEY=Fernet.generate_key().decode())
    with a.app_context():
        db.drop_all(); db.create_all()
        for name, admin in [('admin',True),('alice',False),('bob',False)]:
            u=User(username=name,password_hash=password_hash(name+'-password-123'),is_admin=admin)
            save_keys(u,{'VT_API':name+'-secret'})
            db.session.add(u)
        db.session.commit()
    yield a
    with a.app_context(): db.session.remove(); db.drop_all()

def post(c,path,data,origin='/login'):
    html=c.get(origin,base_url='https://localhost').text
    token=re.search(r'name="csrf_token" value="([^"]+)"',html).group(1)
    return c.post(path,data=dict(data,csrf_token=token),base_url='https://localhost',headers={'Referer':'https://localhost'+origin})
def login(c,name,password=None):
    return post(c,'/login',{'username':name,'password':password or name+'-password-123'})

def test_auth_and_csrf(application):
    c=application.test_client()
    assert c.get('/',base_url='https://localhost').status_code==302
    assert c.get('/admin',base_url='https://localhost').status_code==302
    assert c.post('/',data={'ips':'8.8.8.8'},base_url='https://localhost').status_code==400
    assert c.post('/login',data={},base_url='https://localhost').status_code==400
    assert login(c,'alice','wrong').status_code==401
    r=login(c,'alice'); assert r.status_code==302
    for flag in ['Secure','HttpOnly','SameSite=Lax']: assert flag in r.headers['Set-Cookie']
    assert c.get('/admin',base_url='https://localhost').status_code==403
    assert post(c,'/admin/users/1',{'action':'keys','VT_API':'stolen'},'/').status_code==403
    r=c.get('/',base_url='https://localhost'); assert r.status_code==200
    assert r.headers['Cache-Control']=='no-store' and 'alice-secret' not in r.text

def test_admin_lifecycle(application):
    c=application.test_client(); login(c,'admin')
    post(c,'/admin/users',{'username':'charlie','password':'charlie-password-123'},'/admin')
    with application.app_context(): uid=db.session.execute(db.select(User).filter_by(username='charlie')).scalar_one().id
    path=f'/admin/users/{uid}'
    post(c,path,{'action':'keys','VT_API':'charlie-secret','IPQ_API':'ipqs-secret'},'/admin')
    with application.app_context():
        u=db.session.get(User,uid); assert 'charlie-secret' not in u.encrypted_keys
        assert get_keys(u)['VT_API']=='charlie-secret'
    assert 'charlie-secret' not in c.get('/admin',base_url='https://localhost').text
    post(c,path,{'action':'keys','delete_IPQ_API':'on'},'/admin')
    with application.app_context(): assert get_keys(db.session.get(User,uid))=={'VT_API':'charlie-secret'}
    regular=application.test_client(); login(regular,'charlie')
    post(c,path,{'action':'toggle'},'/admin')
    assert regular.get('/',base_url='https://localhost').status_code==302
    assert login(regular,'charlie').status_code==401
    post(c,path,{'action':'toggle'},'/admin'); login(regular,'charlie')
    post(c,path,{'action':'password','password':'new-password-123'},'/admin')
    assert regular.get('/',base_url='https://localhost').status_code==302
    assert login(regular,'charlie').status_code==401
    assert login(regular,'charlie','new-password-123').status_code==302

def test_isolated_keys(application,monkeypatch):
    captured=[]
    def vt(ip_str,api_key=None): captured.append(api_key); return {'Community Score':'0 / 93'}
    monkeypatch.setattr(web.ip,'analyze_ip_VT',vt)
    for name in ['analyze_ip_ABUSE','analyze_ip_ALIEN','analyze_ip_IPQS','analyze_ip_RDAP_SOC','analyze_ip_BLACKLIST']:
        monkeypatch.setattr(web.ip,name,lambda ip_str,**kwargs:{})
    for name in ['alice','bob']:
        c=application.test_client(); login(c,name)
        assert post(c,'/',{'ips':'8.8.8.8'},'/').status_code==200
    assert captured==['alice-secret','bob-secret']

def test_no_shared_keys_or_secret_errors(application,monkeypatch):
    monkeypatch.setattr(web.ip,'VT_API','shared-secret')
    monkeypatch.setattr(web.ip.requests,'get',lambda *a,**k:pytest.fail('Provider must not be called without user key'))
    for name in ['analyze_ip_VT','analyze_ip_ABUSE','analyze_ip_ALIEN','analyze_ip_IPQS']:
        assert getattr(web.ip,name)('8.8.8.8')['error']=='Sin configurar'
    def fail(ip_str,api_key): raise RuntimeError('URL with '+api_key)
    assert 'private-secret' not in str(web.safe_call(fail,'8.8.8.8',api_key='private-secret'))

def test_logout_and_rate_limit(application):
    c=application.test_client(); login(c,'alice')
    assert post(c,'/logout',{},'/').status_code==302
    assert c.get('/',base_url='https://localhost').status_code==302
    for _ in range(10): assert login(c,'unknown','wrong').status_code==401
    assert login(c,'unknown','wrong').status_code==429

def test_fail_closed(application):
    application.config['API_KEYS_ENCRYPTION_KEY']=None
    assert application.test_client().get('/',base_url='https://localhost').status_code==503
