package com.google.android.gms.internal.mlkit_vision_common;

import androidx.collection.C0208f;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.generated.enums.EnumC4519s1;
import com.quizlet.generated.enums.EnumC4525u1;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.p4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3514p4 {
    public static void a(com.quizlet.infra.contracts.studyfunnel.a aVar, Long l, int i, EnumC4525u1 placement, com.quizlet.generated.enums.w1 subplacement, int i2, int i3, String str, String str2, UUID uuid, Long l2, String str3, int i4) {
        String string;
        Long l3 = (i4 & 1) != 0 ? null : l;
        String str4 = (i4 & 64) != 0 ? null : str;
        UUID uuid2 = (i4 & 256) != 0 ? null : uuid;
        Long l4 = (i4 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? null : l2;
        String str5 = (i4 & 1024) == 0 ? str3 : null;
        com.quizlet.features.infra.basestudy.manager.d dVar = (com.quizlet.features.infra.basestudy.manager.d) aVar;
        dVar.getClass();
        Intrinsics.checkNotNullParameter(placement, "placement");
        Intrinsics.checkNotNullParameter(subplacement, "subplacement");
        EnumC4519s1 enumC4519s1 = EnumC4519s1.IMPRESSION;
        com.quizlet.features.folders.logging.a aVar2 = new com.quizlet.features.folders.logging.a(l4, str5);
        com.quizlet.features.infra.basestudy.manager.b bVar = new com.quizlet.features.infra.basestudy.manager.b(enumC4519s1, l3, i, placement, subplacement, i2, i3, str4, str2, aVar2);
        C0208f c0208fB = dVar.b(i);
        if (c0208fB == null) {
            return;
        }
        if (l3 == null || (string = l3.toString()) == null) {
            string = str2;
        }
        if (uuid2 != null) {
            c0208fB.put(string, uuid2);
        } else {
            Object objRandomUUID = c0208fB.get(string);
            if (objRandomUUID == null) {
                objRandomUUID = UUID.randomUUID();
                c0208fB.put(string, objRandomUUID);
            }
            Intrinsics.d(objRandomUUID);
            uuid2 = (UUID) objRandomUUID;
        }
        UUID uuid3 = uuid2;
        if (Intrinsics.b((com.quizlet.features.infra.basestudy.manager.b) dVar.i.put(uuid3, bVar), bVar)) {
            return;
        }
        StudyFunnelEventLogger.a(dVar.a, enumC4519s1, l3, i, uuid3, placement, subplacement, i2, i3, null, str4, null, aVar2, 1280);
    }

    public static int b(int i) {
        return (int) (Integer.rotateLeft((int) (i * (-862048943)), 15) * 461845907);
    }
}
