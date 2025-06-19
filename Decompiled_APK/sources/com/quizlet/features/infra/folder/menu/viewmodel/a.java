package com.quizlet.features.infra.folder.menu.viewmodel;

import androidx.lifecycle.w0;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.generated.enums.y1;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.q0;

@Metadata
/* loaded from: classes3.dex */
public final class a extends w0 implements n {
    public final m b;

    public a(m delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.b = delegate;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final q0 b() {
        return this.b.k;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void c(com.quizlet.features.infra.folder.menu.data.b option, boolean z) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.b.c(option, z);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void e(com.quizlet.data.interactor.folderstudymaterial.g undoAction) {
        Intrinsics.checkNotNullParameter(undoAction, "undoAction");
        this.b.e(undoAction);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void f(long j, List tags) {
        Intrinsics.checkNotNullParameter(tags, "tags");
        this.b.f(j, tags);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final InterfaceC4992i g() {
        return this.b.i;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final q0 i() {
        return this.b.g;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final InterfaceC4992i j() {
        return this.b.j;
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void k(String studyMaterialId, y1 studyMaterialType, AddMaterialFolderData data) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        Intrinsics.checkNotNullParameter(data, "data");
        this.b.k(studyMaterialId, studyMaterialType, data);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void l(long j, long j2, String folderTitle) {
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        this.b.l(j, j2, folderTitle);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void n() {
        this.b.n();
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void o(String studyMaterialId, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.b.o(studyMaterialId, studyMaterialType);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void p() {
        this.b.p();
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void q(com.quizlet.features.infra.folder.menu.data.g option) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.b.q(option);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void r(com.quizlet.features.infra.folder.menu.data.g option) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.b.r(option);
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final void s() {
        this.b.s();
    }

    @Override // com.quizlet.features.infra.folder.menu.viewmodel.n
    public final InterfaceC4992i u() {
        return this.b.u();
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        this.b.v();
    }
}
