package kotlin.ranges;

import java.util.Iterator;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public abstract class b implements Iterable, kotlin.jvm.internal.markers.a {

    @NotNull
    public static final a d = new a(null);
    public final char a;
    public final char b;
    public final int c = 1;

    public b(char c, char c2) {
        this.a = c;
        this.b = (char) kotlin.internal.c.a(c, c2, 1);
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return new c(this.a, this.b, this.c);
    }
}
