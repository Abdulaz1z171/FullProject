from dto import UserRegisterDTO


def check_validators(dto: UserRegisterDTO):
    assert dto, 'dto cannot be None'
    assert dto.username, 'Username cannot be None'
    assert dto.password, 'Password cannot be None'
