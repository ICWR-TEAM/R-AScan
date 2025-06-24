from colorama import init, Fore, Style

init(autoreset=True)

class Other:
    def __init__(self):
        self.colors = {
            "reset": Style.RESET_ALL,
            "red": Fore.RED,
            "green": Fore.GREEN,
            "yellow": Fore.YELLOW,
            "blue": Fore.BLUE,
            "magenta": Fore.MAGENTA,
            "cyan": Fore.CYAN,
            "bold": Style.BRIGHT,
        }

    def color_text(self, text, color="reset"):
        return f"{self.colors.get(color, Style.RESET_ALL)}{text}{Style.RESET_ALL}"
