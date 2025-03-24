package afishaBMSTU.auth_lib.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
@Builder
public class UserInfoDto<T> {
    private T data;
    private List<String> roles;
}
