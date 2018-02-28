pragma solidity ^0.4.19;

import "./Token.sol";
import "./TokenNetwork.sol";
import "./Utils.sol";

contract TokenNetworkRegistry is Utils {
    string constant public contract_version = "0.3._";

    // Token address => TokenNetwork address
    mapping(address => address) public token_to_token_networks;

    event TokenNetworkCreated(address token_address, address token_network_address);

    function createERC20TokenNetwork(
        address _token_address)
        public
        returns (address token_network_address)
    {
        require(_token_address != 0x0);
        require(contractExists(_token_address));
        require(token_to_token_networks[_token_address] == 0x0);

        // Check if the contract is indeed a token contract
        // TODO we might want to also check for the transfer function/ERC that we support
        require(Token(_token_address).totalSupply() > 0);

        token_network_address = new TokenNetwork(_token_address);

        TokenNetworkCreated(_token_address, token_network_address);

        return token_network_address;
    }
}
