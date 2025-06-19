package assistantMode.refactored.shims;

import androidx.compose.material3.C0675l0;
import assistantMode.refactored.types.StudiableData;
import assistantMode.utils.h;
import com.google.android.gms.internal.mlkit_vision_camera.S2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    /* JADX WARN: Removed duplicated region for block: B:66:0x0105  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.List a(java.util.ArrayList r26, java.util.ArrayList r27) {
        /*
            Method dump skipped, instructions count: 522
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.refactored.shims.b.a(java.util.ArrayList, java.util.ArrayList):java.util.List");
    }

    public static h b(StudiableData studiableData, boolean z, String str) {
        Intrinsics.checkNotNullParameter(studiableData, "<this>");
        a other = new a(studiableData, z, str);
        C0675l0 computeValueIfMissing = new C0675l0(str, 3);
        Intrinsics.checkNotNullParameter(other, "input");
        Intrinsics.checkNotNullParameter(computeValueIfMissing, "computeValueIfMissing");
        a aVar = S2.a;
        if (aVar != null) {
            Intrinsics.checkNotNullParameter(other, "other");
            if (Intrinsics.b(aVar.a, studiableData) && ((z || !aVar.b) && Intrinsics.b(aVar.c, str))) {
                h hVar = S2.b;
                if (hVar != null) {
                    return hVar;
                }
                throw new IllegalStateException("Missing lastStudyableMaterialDataSource, but have matching studiableData.");
            }
        }
        h hVar2 = (h) computeValueIfMissing.invoke(studiableData, Boolean.valueOf(z));
        S2.a = other;
        S2.b = hVar2;
        return hVar2;
    }
}
