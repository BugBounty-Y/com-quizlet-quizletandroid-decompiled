package com.quizlet.features.infra.folder.create.composables;

import com.quizlet.assembly.compose.modals.x;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class a implements Function2 {
    public final /* synthetic */ int a = 3;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public a(DBUser dBUser, DBStudySet dBStudySet, com.quizlet.features.questionnaire.screens.c cVar, boolean z, Y y, Integer num) {
        this.c = dBUser;
        this.e = dBStudySet;
        this.f = cVar;
        this.d = z;
        this.g = y;
        this.b = num;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0026  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x04d0  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0141  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x01cb  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x024a  */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r43, java.lang.Object r44) {
        /*
            Method dump skipped, instructions count: 1328
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.composables.a.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }

    public a(com.quizlet.features.settings.data.models.b bVar, Function1 function1, x xVar, Function0 function0, boolean z, com.quizlet.qutils.string.g gVar) {
        this.e = bVar;
        this.b = function1;
        this.f = xVar;
        this.c = function0;
        this.d = z;
        this.g = gVar;
    }

    public a(com.quizlet.ui.models.content.carditem.f fVar, com.quizlet.features.questionnaire.screens.c cVar, boolean z, Y y, DBStudySet dBStudySet, Integer num) {
        this.c = fVar;
        this.e = cVar;
        this.d = z;
        this.f = y;
        this.g = dBStudySet;
        this.b = num;
    }

    public a(String str, boolean z, androidx.compose.ui.focus.h hVar, Function1 function1, Function0 function0, Function1 function12) {
        this.f = str;
        this.d = z;
        this.e = hVar;
        this.b = function1;
        this.c = function0;
        this.g = function12;
    }

    public a(boolean z, Function0 function0, String str, Function0 function02, String str2, Function1 function1) {
        this.d = z;
        this.c = function0;
        this.f = str;
        this.e = function02;
        this.g = str2;
        this.b = function1;
    }
}
