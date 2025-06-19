package com.quizlet.features.infra.folder.create;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ CreateFolderModalFragment b;

    public /* synthetic */ a(CreateFolderModalFragment createFolderModalFragment, int i, int i2) {
        this.a = i2;
        this.b = createFolderModalFragment;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        CreateFolderModalFragment createFolderModalFragment = this.b;
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        String str = CreateFolderModalFragment.w;
        switch (i) {
            case 0:
                createFolderModalFragment.R(interfaceC0806l, C0776c.H(1));
                break;
            default:
                createFolderModalFragment.Q(interfaceC0806l, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
