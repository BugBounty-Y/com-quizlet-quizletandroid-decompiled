package kotlinx.serialization.json.internal;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class y {
    public static final y c;
    public static final y d;
    public static final y e;
    public static final y f;
    public static final /* synthetic */ y[] g;
    public static final /* synthetic */ kotlin.enums.b h;
    public final char a;
    public final char b;

    static {
        y yVar = new y("OBJ", 0, '{', '}');
        c = yVar;
        y yVar2 = new y("LIST", 1, '[', ']');
        d = yVar2;
        y yVar3 = new y("MAP", 2, '{', '}');
        e = yVar3;
        y yVar4 = new y("POLY_OBJ", 3, '[', ']');
        f = yVar4;
        y[] yVarArr = {yVar, yVar2, yVar3, yVar4};
        g = yVarArr;
        h = AbstractC3328d.f(yVarArr);
    }

    public y(String str, int i, char c2, char c3) {
        this.a = c2;
        this.b = c3;
    }

    public static y valueOf(String str) {
        return (y) Enum.valueOf(y.class, str);
    }

    public static y[] values() {
        return (y[]) g.clone();
    }
}
