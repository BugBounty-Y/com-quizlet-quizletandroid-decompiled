package kotlin.time;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import java.util.concurrent.TimeUnit;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class d {
    public static final d b;
    public static final d c;
    public static final d d;
    public static final d e;
    public static final d f;
    public static final d g;
    public static final /* synthetic */ d[] h;
    public final TimeUnit a;

    static {
        d dVar = new d("NANOSECONDS", 0, TimeUnit.NANOSECONDS);
        b = dVar;
        d dVar2 = new d("MICROSECONDS", 1, TimeUnit.MICROSECONDS);
        d dVar3 = new d("MILLISECONDS", 2, TimeUnit.MILLISECONDS);
        c = dVar3;
        d dVar4 = new d("SECONDS", 3, TimeUnit.SECONDS);
        d = dVar4;
        d dVar5 = new d("MINUTES", 4, TimeUnit.MINUTES);
        e = dVar5;
        d dVar6 = new d("HOURS", 5, TimeUnit.HOURS);
        f = dVar6;
        d dVar7 = new d("DAYS", 6, TimeUnit.DAYS);
        g = dVar7;
        d[] dVarArr = {dVar, dVar2, dVar3, dVar4, dVar5, dVar6, dVar7};
        h = dVarArr;
        AbstractC3328d.f(dVarArr);
    }

    public d(String str, int i, TimeUnit timeUnit) {
        this.a = timeUnit;
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) h.clone();
    }
}
