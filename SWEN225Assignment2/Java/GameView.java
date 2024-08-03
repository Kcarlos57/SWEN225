import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GameView extends JFrame {
    private static GameView instance;
    private Game game;
    private JPanel boardPanel;

    private JPanel boardCellsPanel;

    private JPanel cardPanel;

    private JLabel boardTitle;
    private JPanel infoArea;
    private JTextArea infoAreaText;
    private Map<String,JButton> contextButtons = new HashMap<>();

    /**
     * Retrieves the singleton instance of the GameView class.
     *
     * @return The singleton instance of the GameView class.
     */
    public static GameView getView() {
        if (instance == null) {
            instance = new GameView();
        }
        return instance;
    }

    /**
     * Retrieves the current game instance.
     *
     * @return The current Game instance.
     */
    public Game getGame() {
        return game;
    }

    /**
     * Private constructor for initializing the GameView.
     */
    private GameView() {
        super("Cluedo");

        try {
            // This is set so button.setBackground works correctly
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1000, 600);

        // Initialize components
        boardPanel = new JPanel(); // You can customize this to display the game board
        infoArea = new JPanel(); // You can use this to display player information or game messages
        infoAreaText = new JTextArea();
        infoAreaText.setEditable(false);
        cardPanel = new JPanel();
        boardCellsPanel = new JPanel(){
            @Override
            public void paint(Graphics g) {
                super.paint(g);
                drawBoard(g);
            }
        };

        // JMenu
        JMenuBar menuBar = new JMenuBar();
        JMenu menu = new JMenu("Menu");
        JMenuItem NewGameItem = new JMenuItem("New Game");
        NewGameItem.addActionListener(e -> {
                   GameController.createNewGame();
                });
        JMenuItem quitItem = new JMenuItem("Quit");
        quitItem.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(
                    this,
                    "Are you sure you want to quit the game?",
                    "Confirm Quit",
                    JOptionPane.YES_NO_OPTION
            );
            if (result == JOptionPane.YES_OPTION) {
                System.exit(0);
            }
        });

        // Add a window listener to handle window close
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                confirmQuit();
            }
        });

        menu.add(NewGameItem);
        menu.add(quitItem);

        menuBar.add(menu);
        setJMenuBar(menuBar);

        // Layout components
        setLayout(new BorderLayout());
        add(boardPanel, BorderLayout.WEST);
        add(infoArea, BorderLayout.EAST);

        initializeContextButtons();

        JPanel contextPanel = new JPanel();

        for (JButton button : contextButtons.values()) {
            contextPanel.add(button);
        }

        // Add the roll button in the infoarea panel (use a subpanel to get the layout right)
        infoArea.setLayout(new BorderLayout());
        infoArea.add(infoAreaText, BorderLayout.CENTER);
        infoArea.add(contextPanel, BorderLayout.SOUTH);

        // add title to boardpanel
        boardTitle = new JLabel();
        boardPanel.setLayout(new BorderLayout());

        setVisible(true);

        GameController gameController = GameController.getController();

        // Add the mouse listener to the boardPanel
        boardCellsPanel.addMouseListener(gameController);

        getContentPane().addKeyListener(gameController);
        getContentPane().setFocusTraversalKeysEnabled(false);
        getContentPane().requestFocusInWindow();
    }
    
    /**
     * Initializes the context buttons used in the GUI.
     */
    private void initializeContextButtons() {
        contextButtons.put("roll", new JButton("Roll Dice"));
        contextButtons.put("guess", new JButton("Guess Murder"));
        contextButtons.put("solve", new JButton("Solve Attempt"));
        contextButtons.put("end turn", new JButton("End Turn"));
        contextButtons.put("new game", new JButton("New Game"));
        contextButtons.put("quit", new JButton("Quit"));

        contextButtons.get("roll").addActionListener(e -> GameController.rollDice());
        contextButtons.get("guess").addActionListener(e -> GameController.guessButtonClicked());
        contextButtons.get("solve").addActionListener(e -> GameController.solveButtonClicked());
        contextButtons.get("end turn").addActionListener(e -> GameController.endTurnClicked());
        contextButtons.get("new game").addActionListener(e -> GameController.createNewGame());
        contextButtons.get("quit").addActionListener(e -> confirmQuit());
    }
    
    /**
     * Displays a confirmation dialog for quitting the game.
     */
    void confirmQuit() {
        int result = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to quit the game?",
                "Confirm Quit",
                JOptionPane.YES_NO_OPTION
        );
        if (result == JOptionPane.YES_OPTION) {
            System.exit(0);
        }
    }

    /**
     * Sets the board title.
     * @param title
     */
    public void setBoardTitle(String title){
        SwingUtilities.invokeLater(() -> {
            boardTitle.setText(title);
            boardPanel.revalidate();
        });
    }

    /**
     * Set the context of the game
     * "roll" = Roll Dice
     * "guess" = Guess Murder
     * "solve" = Solve Attempt
     * <p>
     * Clear current buttons, and display ones you've listed here
     * Uses varargs
     *
     * @param context
     * @return
     */
    public GameView setContextButtons(String... context) {
        contextButtons.values().stream().forEach(b -> {b.setVisible(false);});
       int size = context.length;
       if(size==0) return null;

       for (int i = 0; i<size;i++){
           JButton but = contextButtons.getOrDefault(context[i],null);
           if(but==null) throw new IllegalArgumentException("Button " + context[i] + " not found");
           but.setVisible(true);
           
           // Set tooltips based on the context
           switch (context[i]) {
               case "roll":
                   but.setToolTipText("Click to roll two six sided die.");
                   break;
               case "guess":
                   but.setToolTipText("Click to make a guess about the murder.");

                   //Override, disables if has guessed this turn
                   but.setEnabled(!Game.getGameInstance().getIfCurrentPLayerGuessed());
                   break;
               case "solve":
                   but.setToolTipText("Click to attempt to solve the mystery.");

                   //Override, disables solve button if current player has already tried to solve
                   but.setEnabled(!Game.getGameInstance().getCurrentPlayer().getHasGuessed());
                   break;
               // Add more cases and tooltips for other buttons as needed
           }
       }

       return this;
    }

    // You can add methods to update the view based on changes in the game state

    /**
     * Update the boardPanel based on the current game state
     * (center panel)
     */
    public void updateBoard() {
        SwingUtilities.invokeLater(() -> {
            if (Game.getState() == Game.GameState.GameSetup) { return; }

            boardPanel.removeAll();
            boardCellsPanel.setPreferredSize(new Dimension(480, 480)); // Set the size explicitly

            boardPanel.add(boardCellsPanel, BorderLayout.CENTER);
            boardPanel.add(boardTitle, BorderLayout.NORTH);
            boardPanel.add(cardPanel, BorderLayout.SOUTH);

            boardPanel.revalidate();
            boardPanel.repaint();

            // Set the focus to the board panel
            getContentPane().requestFocusInWindow();
        });
    }

    /**
     * Draws the game board using graphics.
     *
     * @param g The Graphics object used for drawing.
     */
    private void drawBoard(Graphics g) {
        Cell[][] board = Game.getGameInstance().getBoard().getBoard();
        if (board == null) throw new NullPointerException("When trying to draw board in view");

        int offset = 20;

        System.out.println("rows: " + board.length + " cols: " + board[0].length);
        for (int row = 0; row < board.length; row++) {
            for (int col = 0; col < board[0].length; col++) {
                Cell cell = board[row][col];
                g.setColor(cell.getColor());
                g.fillRect(col * offset, row * offset, offset, offset);
                g.setColor(Color.BLACK);
                if(cell.getClass() == Person.class) {
                    g.drawString(cell.getDisplayChar(), col * offset + 5, row * offset + 15);
                }
                g.drawRect(col * offset, row * offset, offset, offset);
            }
        }
    }


    /**
     * Update the infoArea based on the current game state
     * (right panel)
     */
    public void updateInfo(String info) {
        SwingUtilities.invokeLater(() -> {
            infoAreaText.setText(info);
            repaint();
        });
    }

    /**
     * Attaches a game instance to the view.
     *
     * @param game The game instance to attach.
     * @return The updated GameView instance.
     */
    public GameView attachGame(Game game) {
        this.game = game;
        displaySetup();
        return this;
    }

    /**
     * Displays the initial setup panel for player selection.
     */
    public void displaySetup() {
        boardPanel.removeAll();

        JPanel setupPanel = new JPanel();
        ButtonGroup playerNumRadioButtons = new ButtonGroup();
        JRadioButton threePlayers = new JRadioButton("3 Players");
        JRadioButton fourPlayers = new JRadioButton("4 Players");

        ActionListener radioButtonListener = e -> {
            SwingUtilities.invokeLater(() -> {
                if (e.getActionCommand().equals("3 Players")) {
                    GameController.setupPlayers(3);
                } else if (e.getActionCommand().equals("4 Players")) {
                    GameController.setupPlayers(4);
                }
                setupPanel.removeAll();
                boardPanel.remove(setupPanel);
                boardPanel.revalidate();
                boardPanel.repaint();
            });
        };

        threePlayers.setActionCommand("3 Players");
        fourPlayers.setActionCommand("4 Players");
        threePlayers.addActionListener(radioButtonListener);
        fourPlayers.addActionListener(radioButtonListener);

        playerNumRadioButtons.add(threePlayers);
        playerNumRadioButtons.add(fourPlayers);

        setupPanel.add(threePlayers);
        setupPanel.add(fourPlayers);

        boardPanel.add(setupPanel);
        boardPanel.revalidate();
        boardPanel.repaint();
    }

    /**
     * Displays the cards held by a player.
     *
     * @param playersCards The list of cards held by the player.
     */
    public void showPlayersCards(List<Card> playersCards) {
        SwingUtilities.invokeLater(() -> {
            cardPanel = new JPanel();
            cardPanel.setLayout(new GridLayout(1, playersCards.size()));
            for (Card card : playersCards) {
                cardPanel.add(new JLabel(card.getCardName()));
            }
            boardPanel.add(cardPanel, BorderLayout.SOUTH);
            boardPanel.revalidate();
        });
    }

    /**
     * Repaints the game board and updates the view.
     */
    public void repaintBoard() {
        SwingUtilities.invokeLater(() -> {
            boardCellsPanel.repaint();
            updateBoard();
        });
    }
}
