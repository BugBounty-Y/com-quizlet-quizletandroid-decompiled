package androidx.compose.ui.text;

/* loaded from: classes.dex */
public final class w {
    public static final w b = new w(false);
    public final boolean a;

    public w() {
        this.a = false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof w) {
            return this.a == ((w) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(0) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(", emojiSupportMatch=EmojiSupportMatch.Default)", new StringBuilder("PlatformParagraphStyle(includeFontPadding="), this.a);
    }

    public w(boolean z) {
        this.a = z;
    }
}
