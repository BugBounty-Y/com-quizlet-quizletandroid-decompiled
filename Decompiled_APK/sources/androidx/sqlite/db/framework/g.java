package androidx.sqlite.db.framework;

import android.content.Context;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes.dex */
public final class g implements androidx.sqlite.db.e {
    public final Context a;
    public final String b;
    public final androidx.sqlite.db.b c;
    public final boolean d;
    public final boolean e;
    public final u f;
    public boolean g;

    public g(Context context, String str, androidx.sqlite.db.b callback, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(callback, "callback");
        this.a = context;
        this.b = str;
        this.c = callback;
        this.d = z;
        this.e = z2;
        this.f = l.b(new androidx.compose.ui.input.nestedscroll.b(this, 28));
    }

    @Override // androidx.sqlite.db.e
    public final b I() {
        return ((f) this.f.getValue()).a(true);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        u uVar = this.f;
        if (uVar.isInitialized()) {
            ((f) uVar.getValue()).close();
        }
    }

    @Override // androidx.sqlite.db.e
    public final void setWriteAheadLoggingEnabled(boolean z) {
        u uVar = this.f;
        if (uVar.isInitialized()) {
            f sQLiteOpenHelper = (f) uVar.getValue();
            Intrinsics.checkNotNullParameter(sQLiteOpenHelper, "sQLiteOpenHelper");
            sQLiteOpenHelper.setWriteAheadLoggingEnabled(z);
        }
        this.g = z;
    }
}
