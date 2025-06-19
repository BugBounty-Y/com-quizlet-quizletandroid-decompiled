package assistantMode.refactored;

import assistantMode.refactored.modelTypes.Card;
import assistantMode.refactored.modelTypes.NSidedCardAnswer;
import assistantMode.refactored.types.RoundProgress;
import assistantMode.refactored.types.StudiableData;
import assistantMode.refactored.types.TotalProgress;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements assistantMode.refactored.interfaces.a {
    public final StudiableData a;
    public final assistantMode.refactored.interfaces.b b;
    public final metering.manager.a c;
    public final grading.core.d d;
    public RoundProgress e;
    public TotalProgress f;

    /* JADX WARN: Removed duplicated region for block: B:29:0x00f7  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x012d  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0173  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public c(assistantMode.refactored.types.StudiableData r21, java.util.ArrayList r22, assistantMode.refactored.types.StudySettings r23, assistantMode.refactored.types.AssistantGradingSettings r24, assistantMode.types.y r25, assistantMode.types.aliases.ExperimentConfiguration r26, java.lang.Long r27, java.util.HashMap r28) throws org.koin.core.error.DefinitionOverrideException, org.koin.core.error.KoinAppAlreadyStartedException {
        /*
            Method dump skipped, instructions count: 401
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.refactored.c.<init>(assistantMode.refactored.types.StudiableData, java.util.ArrayList, assistantMode.refactored.types.StudySettings, assistantMode.refactored.types.AssistantGradingSettings, assistantMode.types.y, assistantMode.types.aliases.ExperimentConfiguration, java.lang.Long, java.util.HashMap):void");
    }

    public static ArrayList b(List list) {
        ArrayList arrayListM = a.m("<this>", list);
        for (Object obj : list) {
            if (obj instanceof NSidedCardAnswer) {
                arrayListM.add(obj);
            }
        }
        return arrayListM;
    }

    public final Y2 a(long j, List answers, boolean z) {
        Intrinsics.checkNotNullParameter(answers, "answers");
        ArrayList arrayListB = b(answers);
        List list = this.a.a;
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (obj instanceof Card) {
                arrayList.add(obj);
            }
        }
        List listA = assistantMode.refactored.shims.b.a(arrayListB, arrayList);
        assistantMode.refactored.interfaces.b bVar = this.b;
        Y2 y2B = bVar.b(listA, z);
        if (bVar.c()) {
            assistantMode.stepGenerators.types.a aVar = (assistantMode.stepGenerators.types.a) y2B;
            Intrinsics.checkNotNullParameter(aVar, "<this>");
            this.e = new RoundProgress(aVar.e.intValue(), aVar.f.intValue());
            Intrinsics.checkNotNullParameter(aVar, "<this>");
            this.f = new TotalProgress(aVar.d, aVar.c);
        }
        return y2B;
    }
}
