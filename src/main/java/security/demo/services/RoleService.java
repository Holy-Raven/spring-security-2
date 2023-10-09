package security.demo.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import security.demo.model.Role;
import security.demo.repositories.RoleRepository;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;

    public Role getUserRole() {
        return roleRepository.findByName("ROLE_USER").get();
    }
}
