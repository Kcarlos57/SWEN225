public class Main {
    public static void main(String[] args) {
        // Create view, attach game to view, and run view
        Game game = Game.getGameInstance();
        game.setup(); // Creates board/initial cards

        GameView.getView()
                .attachGame(game)
                .setContextButtons(); // what buttons to start showing


    }
}
