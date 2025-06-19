package io.ktor.client.statement;

/* loaded from: classes3.dex */
public final class a extends io.ktor.util.pipeline.d {
    public static final androidx.sqlite.db.a f = new androidx.sqlite.db.a("Before", 3);
    public static final androidx.sqlite.db.a g = new androidx.sqlite.db.a("State", 3);
    public static final androidx.sqlite.db.a h = new androidx.sqlite.db.a("After", 3);
    public final boolean e;

    public a() {
        super(f, g, h);
        this.e = true;
    }

    @Override // io.ktor.util.pipeline.d
    public final boolean d() {
        return this.e;
    }
}
