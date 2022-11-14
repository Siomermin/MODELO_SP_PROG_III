<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use \Slim\Routing\RouteCollectorProxy;

require __DIR__ . '/../../vendor/autoload.php';
require_once __DIR__ . "/../poo/Usuario.php";
require_once __DIR__ . "/../poo/Juguete.php";
require_once __DIR__ . "/../poo/MW.php";


$app = AppFactory::create();

$app->get('/', \Usuario::class . ':TraerTodos');

$app->post("/", \Juguete::class . ':AgregarUno')
->add(\MW::class . ':ChequearJWT');
$app->get('/juguetes', \Juguete::class . ':TraerTodos');

$app->post("/login", \Usuario::class . ':VerificarUsuario')
  ->add(\MW::class . ':VerificarSiExisteUsuario')
  ->add(\MW::class . '::ValidarParametrosVacios');
$app->get("/login", \Usuario::class . ':ChequearJWT');

$app->group('/toys', function (RouteCollectorProxy $grupo) {
  $grupo->delete("/{id_juguete}", \Juguete::class . ':BorrarUno');
  $grupo->post("/", \Juguete::class . ':ModificarUno');
})->add(\MW::class . ':ChequearJWT');

$app->group('/tablas', function (RouteCollectorProxy $grupo) {
  $grupo->get('/usuarios', \Usuario::class . ':TraerTodos')
  ->add(\MW::class . '::ListarTablaSinClave');
  $grupo->post('/usuarios', \Usuario::class . ':TraerTodos')
  ->add(\MW::class . '::ListarTablaSinClave')
  ->add(\MW::class . '::ListarEnPdf');
  $grupo->get('/juguetes',  \Juguete::class . ':TraerTodos')
  ->add(\MW::class . '::ListarTablaJuguetes');
})->add(\MW::class . ':ChequearJWT');


//************************************************************************************** */
//************************************************************************************** */
// SOLUCIONES DESPUES DE ENTREGAR EL PARCIAL
$app->post('/usuarios', \Usuario::class . ':AgregarUno')
->add(\MW::class . '::VerificarCorreo')
->add(\MW::class . '::ValidarParametrosVacios')
->add(\MW::class . ':ChequearJWT');

$app->get('/pdf', \Juguete::class . ':ListarPdf')
->add(\MW::class . ':ChequearJWT');


try {
  //CORRE LA APLICACIÓN.
  $app->run();
} catch (Exception $e) {
  // Muestro mensaje de error
  die(json_encode(array("status" => "failed", "message" => "This action is not allowed")));
}
