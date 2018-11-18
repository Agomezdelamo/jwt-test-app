var express = require('express')
var app = express();

app.listen(8999, function() {
    console.log('Api rulando en el puerto 8999!');
});


var bodyParser = require('body-parser')
var jwt = require('jsonwebtoken')
var randtoken = require('rand-token')

var refreshTokens = {};
var SECRET = "SECRETO_PARA_ENCRIPTACION";
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


/////////////*************METODO LOGIN *****************************/
/////////////*************METODO LOGIN *****************************/
/////////////*************METODO LOGIN *****************************/
/////////////*************METODO LOGIN *****************************/

//Metodo que autentica al usuario, recoge el user y pass del body de la petición post
app.post('/login', function(req, res, next) {
    //recogemos el user y pass de la peticion post
    var username = req.body.username;
    var password = req.body.password;

    //establecemos supuestamente despues de validar y movidas varias un objeto user con su rol y todo
    //de esta forma le vamos a pasar al front un chorizo que en el fondo es la identidad de nuestro usuario
    //y su rol, podríamos añadir toda la información que creyesemos oportuna
    var user = {
            'username': username,
            'password': password,
            'role': 'admin'
        }
        //generamos el jwt con la información que queremos que el front tenga sobre nuestro usuario
        //una secret y un tiempo de expiracion
    var token = jwt.sign(user, SECRET, { expiresIn: 20 });


    /**
     * 
     Para el refresh token, simplemente generaremos un UID y lo almacenaremos en un objeto en memoria
      junto con el username del usuario asociado. Lo normal sería guardarlo en una base de datos
       con la información del usuario y la fecha de creación y de expiración 
       (si es que queremos que tenga un tiempo limitado de validez).
     */
    //generamos un refresh token random
    var refreshToken = randtoken.uid(256);

    //simulamos que almacenamos en alguna memoria de refreshtokens como clave el refresh token y 
    //como valor el username, podria ser el objeto entero del usuario, pero hay que tener en cuenta, que si
    //pasa algo con ese usuario en el tiempo entre que usas el accestoken y expira, q se le de baja,
    //que el usuario la lie parda y queramos revocarle..., y si lo almacenamos entero sin validar nada
    //vendrias con el refresh token y lo recuperarias sin problemas
    refreshTokens[refreshToken] = username;

    //creamos el json de respuesta con el jwt y el refresh token para cuando expire el jwt
    res.json({ token: 'JWT ' + token, refreshToken: refreshToken });
});





/////////////************* 2. METODO RENOVAR ACCESS TOKEN *****************************/
/////////////************* 2. METODO RENOVAR ACCESS TOKEN *****************************/
/////////////************* 2. METODO RENOVAR ACCESS TOKEN *****************************/
/////////////************* 2. METODO RENOVAR ACCESS TOKEN *****************************/
/////////////************* 2. METODO RENOVAR ACCESS TOKEN *****************************/

/**
 * Para solicitar un nuevo access token hemos creado el recurso /token. 
 * En él recibimos el refresh token y como control adicional el username del usuario
 * que es dueño del refresh token. Aquí lo que haremos será comprobar que en nuestra lista de refresh tokens
 * está el que nos envían y que tiene el mismo username asociado. Si es correcto, 
 * generamos un nuevo token con la información del usuario (que obtendríamos de la base de datos)
 *  y lo devolvemos.
 * 
 * Si en nuestra aplicación el administrador pudiera deshabilitar usuarios o refresh tokens temporalmente,
 * tendríamos que comprobarlo también antes de generar el nuevo access token.
 */

app.post('/token', function(req, res, next) {
    //extraemos del body del post el username y el refresh token
    var username = req.body.username;
    var refreshToken = req.body.refreshToken;

    //lo buscamos en nuestra base de datos, tanto el token como si ese token tiene ese username
    if ((refreshToken in refreshTokens) && (refreshTokens[refreshToken] == username)) {
        //si se cumple generamos otra vez el objeto usser completo
        var user = {
                'username': username,
                'role': 'admin'
            }
            // generamos el jwt
        var token = jwt.sign(user, SECRET, { expiresIn: 20 })

        //TODO: DEBERIAMOS VOLVER A GENERAR UN REFRESH TOKEN NUEVO Y BORRAR EL ANTIGUO Y TODO LO RELACIONADO?

        // y lo seteamos como json en la respuesta de este rest
        res.json({ token: 'JWT ' + token })
    } else {
        // si no esta el refresh o no coincide con el usuario almacenado mandamos un 401
        res.sendStatus(401)
    }
})



/////////////************* 3. METODO REVOCAR REFRESH TOKEN *****************************/
/////////////************* 3. METODO REVOCAR REFRESH TOKEN *****************************/
/////////////************* 3. METODO REVOCAR REFRESH TOKEN *****************************/
/////////////************* 3. METODO REVOCAR REFRESH TOKEN *****************************/
/////////////************* 3. METODO REVOCAR REFRESH TOKEN *****************************/

/**
 * En una aplicación en la que un usuario puede estar trabajando desde diferentes dispositivos,
 * con una sola identidad (mismo username) pero con tokens diferentes en cada dispositivo,
 * si pierde o le roban uno de estos, este método le permitiría al administrador borrar
 * o deshabilitar el refresh token en cuestión sin necesidad de que el usuario se quede
 * sin servicio en el resto de dispositivos. Ni que tenga que volver a autenticarse,
 * ni cambiar su password, etc. Es decir, podría seguir trabajando sin que le influya en nada 
 * y sin riesgo de que puedan generarle nuevos access tokens desde el dispositivo sustraído. 
 * Es recomendable que los access tokens tengan un tiempo de vida corto para que en casos como este,
 *  se pueda volver a un estado seguro rápidamente.
 * 
 * Para ello hemos creado un recurso /token/reject por el que se puede deshabilitar un refresh token.
 * En este caso simplemente lo borramos de nuestra lista en memoria. 
 * En una implementación completa habría que comprobar que el usuario que hace la petición es administrador
 * o tiene los permisos para este recurso.
 */

app.post('/token/reject', function(req, res, next) {
    var refreshToken = req.body.refreshToken
    if (refreshToken in refreshTokens) {
        delete refreshTokens[refreshToken]
    }
    console.log('borrado refresh token', refreshTokens);
    res.send(204)
})



/////////////************* 4. SOLO TE LO DOY SI ME DAS UN JWT ACCESS TOKEN *****************************/
/////////////************* 4. SOLO TE LO DOY SI ME DAS UN JWT ACCESS TOKEN *****************************/
/////////////************* 4. SOLO TE LO DOY SI ME DAS UN JWT ACCESS TOKEN *****************************/
/////////////************* 4. SOLO TE LO DOY SI ME DAS UN JWT ACCESS TOKEN *****************************/
/////////////************* 4. SOLO TE LO DOY SI ME DAS UN JWT ACCESS TOKEN *****************************/

/**
 * Por último, vamos a exponer un recurso al que sólo se podrá acceder enviando una cabecera con un token JWT
 *  conseguido con anterioridad, y que habrá sido generado por nuestra aplicación
 * y firmado con nuestra clave (SECRET)
 */

// * En primer lugar cargaremos el middleware y los objetos necesarios.
//Passport es un middleware para autenticación en Node.js
var passport = require('passport')

app.use(passport.initialize())
app.use(passport.session())
var JwtStrategy = require('passport-jwt').Strategy
var ExtractJwt = require('passport-jwt').ExtractJwt


/**
 *  Passport require que implementemos el métodos serializeUser 
 * (y dependiendo de la estrategia también el deserializeUser),
 * que sirven para que el middleware almacene el objeto usuario
 * en la sesión con los campos que queramos y le digamos por qué
 * campo queremos que lo indexe. En nuestro ejemplo lo indexamos
 * por el username, pero lo ideal sería usar un ID.
 */
passport.serializeUser(function(user, done) {
    done(null, user.username)
})

/*
passport.deserializeUser(function (username, done) {
  done(null, username)
})
*/


//OBJETO QUE ALMACENA LAS OPCIONES PARA LA JWT STRATEGY
//(son 2, de donde saca el jwt en la cabecera del request y cual es la palabra secreta para desencriptar)
var opts = {}

/**Para la configuración del módulo JWT tenemos que decirle 
 * donde nos va a llegar el token en las peticiones, 
 * (en la cabecera Authorization) */
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme("jwt");
// y cual es la clave para desencriptar los tokens JWT.
opts.secretOrKey = SECRET;

/**
 * Y por último diremos qué queremos hacer con la información extraída del token cada vez que llega 
 * una petición a un recurso que usa esta autenticación. 
 * La variable jwtPayload tendrá el objeto usuario que encriptamos en el login del usuario:
 */
passport.use(new JwtStrategy(opts, function(jwtPayload, done) {
    //1. si el token a expirado devolvemos no autorizado
    var expirationDate = new Date(jwtPayload.exp * 1000)
    if (expirationDate < new Date()) {
        return done(null, false);
    }
    //2. si el token es correcto, obtenemos del token el usuario
    var user = jwtPayload;
    done(null, user)
}))

/**
 * El recurso que vamos a crear para probar la autenticación es /test_jwt. 
 * Y simplemente le diremos a Passport que el acceso a ese path nos lo autentica con la estrategia “jwt”.
 * Esto nos da una idea de que con Passport podemos autenticar cada recurso con una estrategia diferent
 */
app.get('/test_jwt', passport.authenticate('jwt'), function(req, res) {
    res.json({ success: 'enorabuena, estas autenticado con jwt, te voy a dar lo que quieras amigo!', user: req.user })
})