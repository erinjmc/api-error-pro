let express = require('express');
let bodyParser = require('body-parser'); 
let security = require('./security/sec.authentication.js')
let cors = require('cors');
let app = express();
let apiRouter = express.Router();
let port = 3003;
let fs = require('fs');
let dbVersion = '1.0.1'
let corsOptions = {
    origin: 'localhost:4200',
    optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
  }


let errorResponse = { error: true, errorMsg: 'unknown' }

app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(cors(corsOptions));

apiRouter.route('/codes')
    .get((req,res) => {
    let creds = {
        username: req.headers['username'],
        token: req.headers['authorization']
    }
    
    let response = security.authModule.authenticateToken(creds);
        if(!response.error) {
            const tmpData = { 'version': dbVersion, 'stamp': Date.now(), 'codes': JSON.parse(fs.readFileSync('./data/data.json'))}

            response.data = tmpData;
    }
        res.send(response);
    });

    apiRouter.route('/admin/users')
    .get((req,res) => {
        let creds = {
            username: req.headers['username'],
            token: req.headers['authorization']
        }
        let response = security.authModule.authenticateToken(creds);
        if(!response.error) {
            response.data = security.authModule.adminGetUsers(req.body);5
        }
        res.send(response);
    });

apiRouter.route('/auth')
    .post((req, res) => {
        let response = security.authModule.validateCreds(req.body, 'auth');
        if(!response.error) {
            response = security.authModule.authenticateUsernamePassword(req.body);
        }   
        res.send(response);
    });

apiRouter.route('/reset')
    .post((req, res) => {
        let response = security.authModule.validateCreds(req.body, 'reset');
        if(!response.error) {
            response = security.authModule.resetPassword(req.body);
        }
        res.send(response);
    });

apiRouter.route('/new')
    .post((req, res) => {
        let response = security.authModule.validateCreds(req.body, 'new');
        if(!response.error) {
            response = security.authModule.newUser(req.body);
        }
        res.send(response);
    });

apiRouter.route('/logout')
    .post((req, res) => {
        let response = errorResponse;
        if(security.authModule.validateLogout(req.body)) {
            response = security.authModule.logout(req.body);
        }
        res.send(response);   
    });

app.use('/', apiRouter);


app.listen(port, ()=>{
    security.authModule.createDefaultLogon();
    console.log(`Running on port: ${port}`);
});
