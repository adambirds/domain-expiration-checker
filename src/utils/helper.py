def debug(string_to_print, config_options):
    """
       Helper function to assist with printing debug messages.
    """
    if config_options['APP']['DEBUG']:
        print(string_to_print)