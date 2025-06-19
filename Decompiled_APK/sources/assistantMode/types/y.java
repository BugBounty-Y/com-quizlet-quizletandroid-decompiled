package assistantMode.types;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = x.class)
/* loaded from: classes.dex */
public final class y implements serialization.f {

    @NotNull
    public static final SequencingConfiguration$Companion Companion;
    public static final y b;
    public static final y c;
    public static final y d;
    public static final y e;
    public static final y f;
    public static final /* synthetic */ y[] g;
    public final String a;

    static {
        y yVar = new y("LEARN", 0, "LEARN");
        b = yVar;
        y yVar2 = new y("WEB_WRITE", 1, "WEB_WRITE");
        c = yVar2;
        y yVar3 = new y("ANDROID_WRITE", 2, "ANDROID_WRITE");
        d = yVar3;
        y yVar4 = new y("IOS_WRITE", 3, "IOS_WRITE");
        e = yVar4;
        y yVar5 = new y("SPELL", 4, "SPELL");
        f = yVar5;
        y[] yVarArr = {yVar, yVar2, yVar3, yVar4, yVar5};
        g = yVarArr;
        AbstractC3328d.f(yVarArr);
        Companion = new SequencingConfiguration$Companion();
    }

    public y(String str, int i, String str2) {
        this.a = str2;
    }

    public static y valueOf(String str) {
        return (y) Enum.valueOf(y.class, str);
    }

    public static y[] values() {
        return (y[]) g.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
