package afishaBMSTU.auth_lib.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class UserInfoDto<T> {
    private T data;
}
