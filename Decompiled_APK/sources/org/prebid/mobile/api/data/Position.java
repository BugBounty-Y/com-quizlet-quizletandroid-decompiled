package org.prebid.mobile.api.data;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class Position {
    public static final Position a;
    public static final Position b;
    public static final Position c;
    public static final Position d;
    public static final Position e;
    public static final Position f;
    public static final Position g;
    public static final Position h;
    public static final /* synthetic */ Position[] i;

    static {
        Position position = new Position("TOP_LEFT", 0);
        a = position;
        Position position2 = new Position("TOP", 1);
        b = position2;
        Position position3 = new Position("TOP_RIGHT", 2);
        c = position3;
        Position position4 = new Position("RIGHT", 3);
        d = position4;
        Position position5 = new Position("BOTTOM_RIGHT", 4);
        e = position5;
        Position position6 = new Position("BOTTOM", 5);
        f = position6;
        Position position7 = new Position("BOTTOM_LEFT", 6);
        g = position7;
        Position position8 = new Position("LEFT", 7);
        h = position8;
        i = new Position[]{position, position2, position3, position4, position5, position6, position7, position8};
    }

    public static Position a(String str) {
        String lowerCase = str.toLowerCase();
        lowerCase.getClass();
        switch (lowerCase) {
            case "bottomleft":
                return g;
            case "bottom":
                return f;
            case "topleft":
                return a;
            case "topright":
                return c;
            case "bottomright":
                return e;
            case "top":
                return b;
            case "left":
                return h;
            case "right":
                return d;
            default:
                return null;
        }
    }

    public static Position valueOf(String str) {
        return (Position) Enum.valueOf(Position.class, str);
    }

    public static Position[] values() {
        return (Position[]) i.clone();
    }
}
