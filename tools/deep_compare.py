
def deep_compare(alpha, beta):

    # hackish way to compare unicode strings to ascii strings
    if type(alpha) is str:
        alpha = unicode(alpha)
    if type(beta) is str:
        beta = unicode(alpha)

    if type(alpha) is not type(beta):
        return False

    if type(alpha) is dict:
        try:
            return all(
                deep_compare(alpha[key], beta[key]) is True for key in alpha
            )
        except KeyError:
            return False

    if type(alpha) is list:
        alpha_s = sorted(alpha)
        beta_s = sorted(beta)
        return all(
            deep_compare(alpha_s[index], beta_s[index]) is True
            for index in range(len(alpha_s))
        )

    return alpha == beta
