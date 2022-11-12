<?php

use Firebase\JWT\JWT;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Psr7\Response as ResponseMW;

require_once "accesoDatos.php";
require_once "Usuario.php";
require_once __DIR__ . "/autentificadora.php";

class Barbijo 
{
    public int $id;
    public string $color;
    public string $tipo;
    public float $precio;

    // IMPLEMENTACION DE INTERFACE ICRUDSLIM

//     A nivel de aplicación:
// (POST) Alta de autos. Se agregará un nuevo registro en la tabla autos *.
// Se envía un JSON → auto (color, marca, precio y modelo).
// * ID auto-incremental.
// Retorna un JSON (éxito: true/false; mensaje: string; status: 200/418)

    public function AgregarUno(Request $request, Response $response, array $args): Response
    {
        $parametros = $request->getParsedBody();

        $obj_respuesta = new stdclass();
        $obj_respuesta->exito = false;
        $obj_respuesta->mensaje = "No se pudo agregar el barbijo";
        $obj_respuesta->status = 418;

        if (isset($parametros["barbijo"])) {
            $obj = json_decode($parametros["barbijo"]);

            $barbijo = new Barbijo();
            $barbijo->color = $obj->color;
            $barbijo->tipo = $obj->tipo;
            $barbijo->precio = $obj->precio;

            $id_agregado = $barbijo->AgregarBarbijo();
            $barbijo->id = $id_agregado;

            if ($id_agregado) {
                $obj_respuesta->exito = true;
                $obj_respuesta->mensaje = "Barbijo Agregado!";
                $obj_respuesta->status = 200;
            }
        }

        $newResponse = $response->withStatus($obj_respuesta->status);
        $newResponse->getBody()->write(json_encode($obj_respuesta));

        return $newResponse->withHeader('Content-Type', 'application/json');
    }

    public function TraerTodos(Request $request, Response $response, array $args): Response
    {
        $obj_respuesta = new stdClass();
        $obj_respuesta->exito = false;
        $obj_respuesta->mensaje = "No se encontraron barbijos!";
        $obj_respuesta->dato = "{}";
        $obj_respuesta->status = 424;

        $barbijos = Barbijo::TraerBarbijos();

        if (count($barbijos)) {
            $obj_respuesta->exito = true;
            $obj_respuesta->mensaje = "Barbijos encontrados!";
            $obj_respuesta->dato = json_encode($barbijos);
            $obj_respuesta->status = 200;
        }

        $newResponse = $response->withStatus($obj_respuesta->status);
        $newResponse->getBody()->write(json_encode($obj_respuesta));
        return $newResponse->withHeader('Content-Type', 'application/json');
    }

    public function BorrarUno(Request $request, Response $response, array $args): Response
    {
        $obj_respuesta = new stdclass();
        $obj_respuesta->exito = false;
        $obj_respuesta->mensaje = "No se pudo borrar el barbijo";
        $obj_respuesta->status = 418;

        if (
            isset($request->getHeader("token")[0]) &&
            isset($request->getHeader("id_barbijo")[0])
        ) {
            $token = $request->getHeader("token")[0];
            $id = $request->getHeader("id_barbijo")[0];

            $datos_token = Autentificadora::obtenerPayLoad($token);
            $usuario_token = $datos_token->payload->data;
            $perfil_usuario = $usuario_token->perfil;

            if ($perfil_usuario == "propietario") {
                if (Barbijo::BorrarBarbijo($id)) {
                    $obj_respuesta->exito = true;
                    $obj_respuesta->mensaje = "Barbijo Borrado!";
                    $obj_respuesta->status = 200;
                } else {
                    $obj_respuesta->mensaje = "El Barbijo no existe en el listado!";
                }
            } else {
                $obj_respuesta->mensaje = "Usuario no autorizado para realizar la accion. {$usuario_token->nombre} - {$usuario_token->apellido} - {$usuario_token->perfil}";
            }
        }

        $newResponse = $response->withStatus($obj_respuesta->status);
        $newResponse->getBody()->write(json_encode($obj_respuesta));
        return $newResponse->withHeader('Content-Type', 'application/json');
    }

    public function ModificarUno(Request $request, Response $response, array $args): Response
    {
        $obj_respuesta = new stdclass();
        $obj_respuesta->exito = false;
        $obj_respuesta->mensaje = "No se pudo modificar el barbijo";
        $obj_respuesta->status = 418;

        if (
            isset($request->getHeader("token")[0]) &&
            isset($request->getHeader("barbijo")[0])
        ) {
            $token = $request->getHeader("token")[0];
            $obj_json = json_decode($request->getHeader("barbijo")[0]);

            $datos_token = Autentificadora::obtenerPayLoad($token);
            $usuario_token = $datos_token->payload->data;
            $perfil_usuario = $usuario_token->perfil;

            if ($perfil_usuario == "encargado") {
                if ($barbijo = Barbijo::TraerBarbijoPorId($obj_json->id)) {
                    $barbijo->color = $obj_json->color;
                    $barbijo->tipo = $obj_json->tipo;
                    $barbijo->precio = $obj_json->precio;
                    if ($barbijo->ModificarBarbijo()) {
                        $obj_respuesta->exito = true;
                        $obj_respuesta->mensaje = "Barbijo Modificado!";
                        $obj_respuesta->status = 200;
                    } else {
                    }
                } else {
                    $obj_respuesta->mensaje = "El Barbijo no existe en el listado!";
                }
            } else {
                $obj_respuesta->mensaje = "Usuario no autorizado para realizar la accion. {$usuario_token->nombre} - {$usuario_token->apellido} - {$usuario_token->perfil}";
            }
        }

        $newResponse = $response->withStatus($obj_respuesta->status);
        $newResponse->getBody()->write(json_encode($obj_respuesta));
        return $newResponse->withHeader('Content-Type', 'application/json');
    }

    
    // METODOS PARA INTERACTUAR CON EL ORIGEN DE LOS DATOS, EN ESTE CASO UNA BASE DE DATOS

    public function AgregarBarbijo()
    {
        $accesoDatos = AccesoDatos::obtenerObjetoAccesoDatos();

        $consulta = $accesoDatos->retornarConsulta(
            "INSERT INTO barbijos (color, tipo, precio) 
             VALUES(:color, :tipo, :precio)"
        );

        $consulta->bindValue(":color", $this->color, PDO::PARAM_STR);
        $consulta->bindValue(":tipo", $this->tipo, PDO::PARAM_STR);
        $consulta->bindValue(":precio", $this->precio, PDO::PARAM_INT);
        $consulta->execute();

        return $accesoDatos->retornarUltimoIdInsertado();
    }

    public static function TraerBarbijos()
    {
        $accesoDatos = AccesoDatos::obtenerObjetoAccesoDatos();
        $consulta = $accesoDatos->retornarConsulta(
            "SELECT * FROM barbijos"
        );
        $consulta->execute();

        return $consulta->fetchAll(PDO::FETCH_CLASS, "Barbijo");
    }

    public static function TraerBarbijoPorId(int $id)
    {
        $accesoDatos = AccesoDatos::obtenerObjetoAccesoDatos();
        $consulta = $accesoDatos->retornarConsulta(
            "SELECT * FROM barbijos 
             WHERE id = :id"
        );
        $consulta->bindValue(":id", $id, PDO::PARAM_INT);
        $consulta->execute();

        $barbijo = $consulta->fetchObject('Barbijo');

        return $barbijo;
    }

    public static function BorrarBarbijo(int $id)
    {
        $retorno = false;
        $accesoDatos = AccesoDatos::obtenerObjetoAccesoDatos();
        $consulta = $accesoDatos->retornarConsulta("DELETE FROM barbijos WHERE id = :id");
        $consulta->bindValue(":id", $id, PDO::PARAM_INT);
        $consulta->execute();

        $total_borrado = $consulta->rowCount(); // verifico las filas afectadas por la consulta
        if ($total_borrado == 1) {
            $retorno = true;
        }

        return $retorno;
    }

    public function ModificarBarbijo()
    {
        $retorno = false;

        $accesoDatos = AccesoDatos::obtenerObjetoAccesoDatos();

        $consulta = $accesoDatos->retornarConsulta(
            "UPDATE barbijos
             SET color = :color, tipo = :tipo, precio = :precio
             WHERE id = :id"
        );

        $consulta->bindValue(":id", $this->id, PDO::PARAM_INT);
        $consulta->bindValue(":color", $this->color, PDO::PARAM_STR);
        $consulta->bindValue(":tipo", $this->tipo, PDO::PARAM_STR);
        $consulta->bindValue(":precio", $this->precio, PDO::PARAM_INT);
        $consulta->execute();

        $total_modificado = $consulta->rowCount(); // verifico las filas afectadas por la consulta
        if ($total_modificado == 1) {
            $retorno = true;
        }

        return $retorno;
    }
}
