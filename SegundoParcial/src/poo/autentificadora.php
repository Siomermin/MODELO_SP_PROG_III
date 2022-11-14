<?php
use Firebase\JWT\JWT;

class Autentificadora
{
    private static string $secret_key = 'ClaveSuperSecreta@';
    private static array $encrypt = ['HS256'];
    private static string $aud = "";
    
    public static function crearJWT( $data, int $exp = (60*5)) : string
    {
        $time = time();
        self::$aud = self::aud();

        $token = array(
        	'iat'=>$time,
            'exp' => $time + $exp,
            'aud' => self::$aud,
            'usuario' => $data[0],
            'alumno' => $data[1],
            'parcial'=> $data[2]
        );

        return JWT::encode($token, self::$secret_key);
    }
    
    public static function verificarJWT(string $token) : stdClass
    {
        $datos = new stdClass();
        $datos->verificado = FALSE;
        $datos->mensaje = "";

        try 
        {
            if( ! isset($token))
            {
                $datos->mensaje = "Token vacío!!!";
            }
            else
            {          
                $decode = JWT::decode(
                    $token,
                    self::$secret_key,
                    self::$encrypt
                );

                if($decode->aud !== self::aud())
                {
                    throw new Exception("Usuario inválido!!!");
                }
                else
                {
                    $datos->verificado = TRUE;
                    $datos->mensaje = "Token OK!!!";
                } 
            }          
        } 
        catch (Exception $e) 
        {
            $datos->mensaje = "Token inválido!!! - " . $e->getMessage();
        }
    
        return $datos;
    }
    
    public static function obtenerPayLoad(string $token) : object
    {
        $datos = new stdClass();
        $datos->exito = FALSE;
        $datos->payload = NULL;
        $datos->mensaje = "";

        try {

            $datos->payload = JWT::decode(
                                            $token,
                                            self::$secret_key,
                                            self::$encrypt
                                        );
            $datos->exito = TRUE;

        } catch (Exception $e) { 

            $datos->mensaje = $e->getMessage();
        }

        return $datos;
    }
    
    private static function aud() : string
    {
        $aud = new stdClass();
        $aud->ip_visitante = "";

        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $aud->ip_visitante = $_SERVER['HTTP_CLIENT_IP'];
        } 
        elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $aud->ip_visitante = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $aud->ip_visitante = $_SERVER['REMOTE_ADDR'];//La dirección IP desde la cual está viendo la página actual el usuario.
        }
        
        $aud->user_agent = @$_SERVER['HTTP_USER_AGENT'];
        $aud->host_name = gethostname();
        
        return json_encode($aud);//sha1($aud);
    }

}