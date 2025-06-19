package com.quizlet.features.folders.edittags.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.work.impl.model.e;
import com.google.android.gms.internal.mlkit_vision_document_scanner.A6;
import com.quizlet.data.model.EnumC4159q0;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.features.folders.edittags.data.d;
import com.quizlet.features.folders.edittags.data.f;
import com.quizlet.features.folders.edittags.data.g;
import java.util.Set;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class c extends w0 {
    public final com.quizlet.data.repository.qclass.c b;
    public final e c;
    public final com.quizlet.data.repository.explanations.myexplanations.a d;
    public final FolderLogger e;
    public final long f;
    public final s0 g;
    public final d0 h;
    public Long i;
    public String j;
    public Set k;

    public c(m0 savedStateHandle, com.quizlet.data.repository.qclass.c updateFolderUseCase, e deleteSubfolderUseCase, com.quizlet.data.repository.explanations.myexplanations.a validateTagUseCase, FolderLogger folderLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(updateFolderUseCase, "updateFolderUseCase");
        Intrinsics.checkNotNullParameter(deleteSubfolderUseCase, "deleteSubfolderUseCase");
        Intrinsics.checkNotNullParameter(validateTagUseCase, "validateTagUseCase");
        Intrinsics.checkNotNullParameter(folderLogger, "folderLogger");
        this.b = updateFolderUseCase;
        this.c = deleteSubfolderUseCase;
        this.d = validateTagUseCase;
        this.e = folderLogger;
        Long l = (Long) savedStateHandle.a("folderId");
        this.f = l != null ? l.longValue() : 0L;
        this.g = e0.c(g.d);
        this.h = e0.b(0, 0, null, 7);
        this.k = M.a;
    }

    public final void A(f event) {
        Object value;
        String label;
        boolean z;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean z2 = event instanceof com.quizlet.features.folders.edittags.data.a;
        long j = this.f;
        FolderLogger folderLogger = this.e;
        if (z2) {
            com.quizlet.features.folders.edittags.data.a aVar = (com.quizlet.features.folders.edittags.data.a) event;
            this.i = Long.valueOf(aVar.a);
            String str = aVar.b;
            this.j = str;
            this.k = CollectionsKt.A0(aVar.c);
            folderLogger.u(j, str);
            B(str);
            return;
        }
        if (event instanceof com.quizlet.features.folders.edittags.data.b) {
            B(((com.quizlet.features.folders.edittags.data.b) event).a);
            return;
        }
        if (event.equals(d.a)) {
            E.A(p0.j(this), null, null, new a(this, null), 3);
            return;
        }
        boolean zEquals = event.equals(com.quizlet.features.folders.edittags.data.e.a);
        s0 s0Var = this.g;
        if (!zEquals) {
            if (!event.equals(com.quizlet.features.folders.edittags.data.c.a)) {
                throw new NoWhenBranchMatchedException();
            }
            folderLogger.s(j, ((g) s0Var.getValue()).a);
            return;
        }
        EnumC4159q0 invalidTagType = A6.a(this.d, ((g) s0Var.getValue()).a, this.k);
        if (invalidTagType == EnumC4159q0.a) {
            E.A(p0.j(this), null, null, new b(this, null), 3);
            return;
        }
        do {
            value = s0Var.getValue();
            label = ((g) s0Var.getValue()).a;
            z = ((g) value).b;
            Intrinsics.checkNotNullParameter(label, "label");
            Intrinsics.checkNotNullParameter(invalidTagType, "invalidTagType");
        } while (!s0Var.k(value, new g(label, z, invalidTagType)));
    }

    public final void B(String label) {
        s0 s0Var;
        Object value;
        boolean z;
        EnumC4159q0 invalidTagType = this.d.l(label);
        do {
            s0Var = this.g;
            value = s0Var.getValue();
            g gVar = (g) value;
            String string = StringsKt.g0(label).toString();
            String str = this.j;
            if (str == null) {
                str = "";
            }
            z = !Intrinsics.b(string, str);
            gVar.getClass();
            Intrinsics.checkNotNullParameter(label, "label");
            Intrinsics.checkNotNullParameter(invalidTagType, "invalidTagType");
        } while (!s0Var.k(value, new g(label, z, invalidTagType)));
    }
}
