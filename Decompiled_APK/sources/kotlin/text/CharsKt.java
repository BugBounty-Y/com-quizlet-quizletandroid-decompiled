package kotlin.text;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class CharsKt extends C4962a {
    private CharsKt() {
    }

    public static boolean b(char c) {
        return Character.isWhitespace(c) || Character.isSpaceChar(c);
    }
}
