package androidx.sqlite.db;

import android.content.Context;
import androidx.camera.camera2.internal.m0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public class c {
    public final Context a;
    public String b;
    public b c;
    public boolean d;
    public boolean e;

    public c(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    public final m0 a() {
        String str;
        b bVar = this.c;
        if (bVar == null) {
            throw new IllegalArgumentException("Must set a callback to create the configuration.");
        }
        if (this.d && ((str = this.b) == null || str.length() == 0)) {
            throw new IllegalArgumentException("Must set a non-null database name to a configuration that uses the no backup directory.");
        }
        return new m0(this.a, this.b, bVar, this.d, this.e);
    }
}
