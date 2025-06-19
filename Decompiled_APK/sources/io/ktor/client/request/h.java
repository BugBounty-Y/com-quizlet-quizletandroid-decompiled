package io.ktor.client.request;

/* loaded from: classes3.dex */
public final class h extends io.ktor.util.pipeline.d {
    public static final androidx.sqlite.db.a f = new androidx.sqlite.db.a("Before", 3);
    public static final androidx.sqlite.db.a g = new androidx.sqlite.db.a("State", 3);
    public static final androidx.sqlite.db.a h = new androidx.sqlite.db.a("Monitoring", 3);
    public static final androidx.sqlite.db.a i = new androidx.sqlite.db.a("Engine", 3);
    public static final androidx.sqlite.db.a j = new androidx.sqlite.db.a("Receive", 3);
    public final boolean e;

    public h() {
        super(f, g, h, i, j);
        this.e = true;
    }

    @Override // io.ktor.util.pipeline.d
    public final boolean d() {
        return this.e;
    }
}
