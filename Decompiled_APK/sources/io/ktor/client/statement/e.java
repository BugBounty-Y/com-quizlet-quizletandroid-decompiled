package io.ktor.client.statement;

/* loaded from: classes3.dex */
public final class e extends io.ktor.util.pipeline.d {
    public static final androidx.sqlite.db.a f = new androidx.sqlite.db.a("Receive", 3);
    public static final androidx.sqlite.db.a g = new androidx.sqlite.db.a("Parse", 3);
    public static final androidx.sqlite.db.a h = new androidx.sqlite.db.a("Transform", 3);
    public static final androidx.sqlite.db.a i = new androidx.sqlite.db.a("State", 3);
    public static final androidx.sqlite.db.a j = new androidx.sqlite.db.a("After", 3);
    public final boolean e;

    public e() {
        super(f, g, h, i, j);
        this.e = true;
    }

    @Override // io.ktor.util.pipeline.d
    public final boolean d() {
        return this.e;
    }
}
