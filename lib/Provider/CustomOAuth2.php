<?php

namespace OCA\SocialLogin\Provider;

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Data;
use Hybridauth\Exception\UnexpectedApiResponseException;
use Hybridauth\HttpClient\HttpClientInterface;
use Hybridauth\Logger\LoggerInterface;
use Hybridauth\Storage\StorageInterface;
use Hybridauth\User;

class CustomOAuth2 extends OAuth2
{

    public function __construct(
        $config = [],
        HttpClientInterface $httpClient = null,
        StorageInterface $storage = null,
        LoggerInterface $logger = null
    ) {
        parent::__construct($config, $httpClient, $storage, $logger);
        $this->providerId = $this->clientId;
    }

    /**
     * @return User\Profile
     * @throws UnexpectedApiResponseException
     * @throws \Hybridauth\Exception\HttpClientFailureException
     * @throws \Hybridauth\Exception\HttpRequestFailedException
     * @throws \Hybridauth\Exception\InvalidAccessTokenException
     */
    public function getUserProfile()
    {
        $profileFields = $this->strToArray($this->config->get('profile_fields'));
        $profileUrl = $this->config->get('endpoints')['profile_url'];

        if (count($profileFields) > 0) {
            // profile fields: id,displayName,onPremisesImmutableId,mail
            // scopes: openid email profile User.Read profile offline_access
            $profileUrl .= (strpos($profileUrl, '?') !== false ? '&' : '?') . '$select=' . implode(',', $profileFields);
        }

        $response = $this->apiRequest($profileUrl);
        if (isset($response->ocs->data)) {
            $response = $response->ocs->data;
        }

        $displayNameClaim = $this->config->get('displayname_claim');
        $response->displayName = $response->$displayNameClaim
            ?? $response->displayName
            ?? $response->username
            ?? null
        ;

        $data = new Data\Collection($response);

        $userProfile = new User\Profile();
        foreach ($data->toArray() as $key => $value) {
            if ($key !== 'data' && property_exists($userProfile, $key)) {
                $userProfile->$key = $value;
            }
        }

        if (null !== $groups = $this->getGroups($data)) {
            $userProfile->data['groups'] = $groups;
        }
        if ($groupMapping = $this->config->get('group_mapping')) {
            $userProfile->data['group_mapping'] = $groupMapping;
        }

        $userProfile->email = $data->get('mail');
        $onPremisesImmutableId = $data->get('onPremisesImmutableId');
        // in Azure AD, the onPremisesImmutableId is a base64 encoding of ObjectGUID
        $userProfile->identifier = CustomOAuth2::getDeserializedObjectGuid($onPremisesImmutableId);
        return $userProfile;
    }

    public static function getDeserializedObjectGuid($base64)
    {
        $binary = base64_decode($base64);
        $lowerHex = bin2hex($binary);
        $hex = strtoupper($lowerHex);

        $guid = substr($hex, 6, 2) . substr($hex, 4, 2) . substr($hex, 2, 2) . substr($hex, 0, 2) . "-"
            . substr($hex, 10, 2) . substr($hex, 8, 2) . "-"
            . substr($hex, 14, 2) . substr($hex, 12, 2) . "-"
            . substr($hex, 16, 2) . substr($hex, 18, 2) . "-"
            . substr($hex, 20);
        return $guid;
    }

    protected function getGroups(Data\Collection $data)
    {
        if ($groupsClaim = $this->config->get('groups_claim')) {
            $nestedClaims = explode('.', $groupsClaim);
            $claim = array_shift($nestedClaims);
            $groups = $data->get($claim);
            while (count($nestedClaims) > 0) {
                $claim = array_shift($nestedClaims);
                if (!isset($groups->{$claim})) {
                    $groups = [];
                    break;
                }
                $groups = $groups->{$claim};
            }
            if (is_array($groups)) {
                return $groups;
            } elseif (is_string($groups)) {
                return $this->strToArray($groups);
            }
            return [];
        }
        return null;
    }

    private function strToArray($str)
    {
        return array_filter(
            array_map('trim', explode(',', $str)),
            function ($val) { return $val !== ''; }
        );
    }
}
