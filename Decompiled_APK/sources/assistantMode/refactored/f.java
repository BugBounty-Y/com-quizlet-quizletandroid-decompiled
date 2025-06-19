package assistantMode.refactored;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = e.class)
/* loaded from: classes.dex */
public final class f implements serialization.f {

    @NotNull
    public static final StudyMode$Companion Companion;
    public static final f b;
    public static final f c;
    public static final /* synthetic */ f[] d;
    public final String a;

    static {
        f fVar = new f("LEARN", 0, "LEARN");
        b = fVar;
        f fVar2 = new f("ANDROID_WRITE", 1, "ANDROID_WRITE");
        c = fVar2;
        f[] fVarArr = {fVar, fVar2, new f("IOS_WRITE", 2, "IOS_WRITE"), new f("WEB_WRITE", 3, "WEB_WRITE"), new f("SPELL", 4, "SPELL")};
        d = fVarArr;
        AbstractC3328d.f(fVarArr);
        Companion = new StudyMode$Companion();
    }

    public f(String str, int i, String str2) {
        this.a = str2;
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) d.clone();
    }

    @Override // serialization.f
    public final String getValue() {
        return this.a;
    }
}
