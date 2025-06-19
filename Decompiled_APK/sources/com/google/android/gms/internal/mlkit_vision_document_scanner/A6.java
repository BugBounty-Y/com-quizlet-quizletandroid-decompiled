package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.quizlet.data.model.EnumC4159q0;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class A6 {
    public static final /* synthetic */ int a = 0;

    public static EnumC4159q0 a(com.quizlet.data.repository.explanations.myexplanations.a aVar, String tag, Set currentTags) {
        EnumC4159q0 enumC4159q0;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(currentTags, "currentTags");
        Intrinsics.checkNotNullParameter(currentTags, "currentTags");
        EnumC4159q0 enumC4159q02 = currentTags.size() < 30 ? EnumC4159q0.a : EnumC4159q0.d;
        EnumC4159q0 enumC4159q03 = EnumC4159q0.d;
        FolderLogger folderLogger = (FolderLogger) aVar.b;
        if (enumC4159q02 == enumC4159q03) {
            folderLogger.l();
            return enumC4159q03;
        }
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(currentTags, "currentTags");
        LinkedHashSet linkedHashSetF = kotlin.collections.b0.f(currentTags, kotlin.collections.Z.b((String) aVar.c));
        if (linkedHashSetF.isEmpty()) {
            enumC4159q0 = EnumC4159q0.a;
        } else {
            Iterator it2 = linkedHashSetF.iterator();
            while (it2.hasNext()) {
                if (kotlin.text.D.l(tag, (String) it2.next(), true)) {
                    enumC4159q0 = EnumC4159q0.c;
                    break;
                }
            }
            enumC4159q0 = EnumC4159q0.a;
        }
        EnumC4159q0 enumC4159q04 = EnumC4159q0.c;
        if (enumC4159q0 == enumC4159q04) {
            return enumC4159q04;
        }
        EnumC4159q0 enumC4159q0L = aVar.l(tag);
        EnumC4159q0 enumC4159q05 = EnumC4159q0.b;
        if (enumC4159q0L != enumC4159q05) {
            return EnumC4159q0.a;
        }
        folderLogger.m(tag);
        return enumC4159q05;
    }
}
