package io.ktor.client.request;

/* loaded from: classes3.dex */
public final class f extends io.ktor.util.pipeline.d {
    public static final androidx.sqlite.db.a f = new androidx.sqlite.db.a("Before", 3);
    public static final androidx.sqlite.db.a g = new androidx.sqlite.db.a("State", 3);
    public static final androidx.sqlite.db.a h = new androidx.sqlite.db.a("Transform", 3);
    public static final androidx.sqlite.db.a i = new androidx.sqlite.db.a("Render", 3);
    public static final androidx.sqlite.db.a j = new androidx.sqlite.db.a("Send", 3);
    public final boolean e;

    public f() {
        super(f, g, h, i, j);
        this.e = true;
    }

    @Override // io.ktor.util.pipeline.d
    public final boolean d() {
        return this.e;
    }
}
