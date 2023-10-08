package security.demo.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequiredArgsConstructor
public class MainController {

    @GetMapping("/unsecured")
    public String unsecuredDate() {
        return "unsecured date";
    }

    @GetMapping("/secured")
    public String securedDate() {
        return "secured date";
    }

    @GetMapping("/admin")
    public String adminDate() {
        return "admin date";
    }

    @GetMapping("/info")
    public String userDate(Principal principal) {
        return principal.getName();
    }
}
