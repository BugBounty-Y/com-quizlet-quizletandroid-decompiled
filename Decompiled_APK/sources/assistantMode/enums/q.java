package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = p.class)
/* loaded from: classes.dex */
public final class q implements serialization.b {

    @NotNull
    public static final StudiableMetadataStatus$Companion Companion;
    public static final q b;
    public static final q c;
    public static final q d;
    public static final q e;
    public static final /* synthetic */ q[] f;
    public final int a;

    static {
        q qVar = new q("INFERENCES_UNAVAILABLE", 0, 0);
        b = qVar;
        q qVar2 = new q("INFERENCES_PENDING", 1, 1);
        c = qVar2;
        q qVar3 = new q("INFERENCES_READY", 2, 2);
        d = qVar3;
        q qVar4 = new q("INFERENCES_ERROR", 3, 3);
        e = qVar4;
        q[] qVarArr = {qVar, qVar2, qVar3, qVar4};
        f = qVarArr;
        AbstractC3328d.f(qVarArr);
        Companion = new StudiableMetadataStatus$Companion();
    }

    public q(String str, int i, int i2) {
        this.a = i2;
    }

    public static q valueOf(String str) {
        return (q) Enum.valueOf(q.class, str);
    }

    public static q[] values() {
        return (q[]) f.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
