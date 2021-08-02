## SecretFinder Regex List
Foram adicionados outros regex de APIs a lista padrão do SecretFinder

### Adicionar Regex
Abrir o script SecretFinder.py e adicionar o regex:

```py
_regex = {
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic\s*[a-zA-Z0-9=:_\+\/-]+',
    'authorization_bearer' : r'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
    'authorization_api' : r'api[key|\s*]+[a-zA-Z0-9_\-]+',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'artifactory_api_token' : r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}',
    'artifactory_password' : r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}',
    'AWS_Client_ID' : r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
    "Amazon_AWS_Secret_Access_Key": r"[\\s][a-zA-Z0-9]{40}[\\s]",
    "Facebook_OAuth": r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
    "Generic_API_Key": r"[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": r"[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "GitHub": r"[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "GitLab_PAT": r"(_|-?)([t|T][o|O][k|K][e|E][n|N])(:|=| )(.{0,3})(\\S{20})(.?)(\\n|\\r|\\n\\r|$)",
    "Google_(GCP)_Service-account": r"\"type\": \"service_account\"",
    "Google_Cloud_Platform_API_Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google_Cloud_Platform_OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google_Drive_OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google_YouTube_OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Heroku_API_Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "MailChimp_API_Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Password_in_URL": r"[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "Picatic_API_Key": r"sk_live_[0-9a-z]{32}",
    "Send_Grid_API": r"SG\\.[a-zA-Z0-9]{22}\\.[a-zA-Z0-9]{43}",
    "Slack_Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
    "Slack_Webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Twitter_Access_Token": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter_OAuth": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
    'Cloudinary_Basic_Auth' : r'cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+',
    'LinkedIn_Secret_Key' : r'(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]',
    'MD5_Hash' : r'[a-f0-9]{32}'

}
```
