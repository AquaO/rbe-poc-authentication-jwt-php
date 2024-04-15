<?php

namespace App\Controller;

use Nowakowskir\JWT\JWT;
use Nowakowskir\JWT\TokenDecoded;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class ApiController extends AbstractController
{
    private readonly string $BASE_API_SERVICE;

    public function __construct(
        private readonly LoggerInterface     $logger,
        private readonly HttpClientInterface $httpClient,
        private RequestStack $requestStack,
    )
    {
        $this->BASE_API_SERVICE = "/api/public/client/aquao-authorization/";
    }

    #[Route('/', name: 'app_home')]
    public function index(): Response
    {
        return $this->render('home/index.html.twig', [
            'isLog' => false
        ]);
    }

    #[Route('/login', name: 'app_login')]
    public function login(): Response
    {
        $this->logger->info('> /login');

        $this->requestStack->getSession()->start();
        $result = $this->authenticateWithJWT();

        if (empty($result)) {
            return $this->render('home/index.html.twig', [
                'isLog' => false
            ]);
        }

        return $this->render('home/index.html.twig', [
            'isLog' => true
        ]);
    }

    private function authenticateWithJWT(): array
    {
        $this->logger->info("> " . $this->BASE_API_SERVICE );
        $token = $this->GenerateToken();

        $url = $_ENV['HOST'] . $this->BASE_API_SERVICE . $token;

        try {
            // Send request to the API services with the JWT token and a cookie with the session ID
            $response = $this->httpClient
                ->withOptions([
                'headers' => [
                    'Cookie' => new Cookie($_ENV['SESSION_NAME'], $this->requestStack->getSession()->get("sessionId"), strtotime('+1 day')),
                    'Accept' => 'application/json',
                ],
            ])
                ->request('GET', $url);

            $this->requestStack->getSession()->set('principalName', $response->toArray()['email']);
            $this->getSessionID($response);
            $this->logger->info('Principal: \'' . $this->requestStack->getSession()->get("principalName") . '\' with SESSION \'' . $this->requestStack->getSession()->get("sessionId") . '\'');
            return $response->toArray();
        } catch (\Exception $e) {
            $this->logger->error('Error: ' . $e->getMessage());
        } catch (TransportExceptionInterface $e) {
            $this->logger->error('Error Request: ' . $e->getMessage());
        }

        return [];
    }

    #[Route('/whoami', name: 'app_whoami')]
    public function whoami(): Response
    {
        $this->logger->info('> /whoami');

        $url = $_ENV['HOST'];
        $options = [];

        if($this->requestStack->getSession()->get('sessionId') !== null) {
            $options = [
                'headers' => [
                    'Cookie' => new Cookie($_ENV['SESSION_NAME'], $this->requestStack->getSession()->get('sessionId'), strtotime('+1 hour'))
                ],
            ];
        }

        try {
            $url = $url . '/api/whoami';
            $response = $this->httpClient
                ->withOptions($options)
                ->request('GET', $url);
                
            $this->getSessionID($response);
            $this->requestStack->getSession()->set('principalName', $response->toArray()['name']);
            $this->logger->info('Principal: \'' . $this->requestStack->getSession()->get('sessionId') . '\' with SESSION \'' . $this->requestStack->getSession()->get('sessionId') . '\'');

            return $this->render('home/index.html.twig', [
                'isLog' => true,
                'principal' => $this->requestStack->getSession()->get('principalName'),
                'sessionId' => $this->requestStack->getSession()->get('sessionId')
            ]);

        } catch (\Exception $e) {
            $this->logger->error('Error: ' . $e->getMessage());

            return $this->render('home/index.html.twig', [
                'isLog' => false
            ]);
        }
    }

    private function getSessionID($response): void
    {
        if(!isset($response->getHeaders()['set-cookie'])) {
            return;
        }

        $cookies = $response->getHeaders()['set-cookie'];

        foreach ($cookies as $cookie) {
            $parts = null;
            preg_match('/(^|, )' . preg_quote($_ENV['SESSION_NAME']) . '=([^;]+); /', $cookie, $parts);
            if ($parts[2]) {
                $this->requestStack->getSession()->set('sessionId', $parts[2]);
                break;
            } else {
                $this->logger->error('Session ID not found');
            }
        }
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(): Response
    {
        $this->logger->info('> /logout');

        $response = $this->httpClient->request('GET', $_ENV['HOST'] . '/api/logout');
        $this->getSessionID($response);
        $this->requestStack->getSession()->set('principalName', $response->toArray()['name']);
        $this->logger->info('Principal: \'' . $this->requestStack->getSession()->get('principalName') . '\' with SESSION \'' . $this->requestStack->getSession()->get('sessionId') . '\'');

        return $this->redirectToRoute('app_home');
    }

    private function GenerateToken(): string
    {
        $secret = $_ENV['JWT_KEY'];

        $header = [
            "alg" => "HS256",
            "typ" => "JWT",
        ];

        $payload = [
            "iat" => time(),
            "exp" => time() + 60 * 25, // 30 minutes
            "iss" => $_ENV['JWT_ISSUER'],
            "sub" => $_ENV['JWT_SUBJECT'],
        ];

        $token = new TokenDecoded($payload, $header);
        $token = $token->encode(base64_decode($secret), JWT::ALGORITHM_HS256);

        return $token->toString();
    }
}
