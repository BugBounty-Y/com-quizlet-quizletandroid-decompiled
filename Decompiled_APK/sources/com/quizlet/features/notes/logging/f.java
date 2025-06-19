package com.quizlet.features.notes.logging;

import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.generated.enums.EnumC4471c0;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends a {
    public static final /* synthetic */ int d = 0;

    public static void d(f fVar, String inputType, Integer num, List fileTypes, int i) {
        if ((i & 2) != 0) {
            num = null;
        }
        if ((i & 4) != 0) {
            fileTypes = K.a;
        }
        fVar.getClass();
        Intrinsics.checkNotNullParameter(inputType, "inputType");
        Intrinsics.checkNotNullParameter(fileTypes, "fileTypes");
        NotesEventLog.Companion companion = NotesEventLog.b;
        String strA = EnumC4471c0.RECEIVED_FROM_OTHER_APP.a();
        androidx.lifecycle.compose.d dVar = new androidx.lifecycle.compose.d(num, fileTypes, inputType, 12);
        companion.getClass();
        fVar.a(NotesEventLog.Companion.a(a.b, strA, dVar));
    }

    public final void b(boolean z, Integer num, List fileTypes, String inputType) {
        Intrinsics.checkNotNullParameter(fileTypes, "fileTypes");
        Intrinsics.checkNotNullParameter(inputType, "inputType");
        NotesEventLog.Companion companion = NotesEventLog.b;
        String strA = EnumC4471c0.IMPORT_START.a();
        e eVar = new e(z, num, fileTypes, inputType, 0);
        companion.getClass();
        a(NotesEventLog.Companion.a(a.b, strA, eVar));
    }

    public final void c(String str, Integer num, List fileTypes, String inputType) {
        Intrinsics.checkNotNullParameter(fileTypes, "fileTypes");
        Intrinsics.checkNotNullParameter(inputType, "inputType");
        NotesEventLog.Companion companion = NotesEventLog.b;
        String strA = EnumC4471c0.IMPORT_SUCCESS.a();
        androidx.navigation.internal.e eVar = new androidx.navigation.internal.e(str, num, fileTypes, inputType, 5);
        companion.getClass();
        a(NotesEventLog.Companion.a(a.b, strA, eVar));
    }
}
