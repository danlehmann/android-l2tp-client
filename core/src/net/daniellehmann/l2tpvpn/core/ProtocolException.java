package net.daniellehmann.l2tpvpn.core;

/** A malformed or unexpected protocol message, or a negotiation failure. */
public class ProtocolException extends Exception {
    private static final long serialVersionUID = 1L;

    public ProtocolException(String message) {
        super(message);
    }

    public ProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}
