package com.quizlet.quizletandroid.ui.group.classcontent.adapter;

import android.view.View;
import androidx.fragment.app.AbstractC1136h0;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModePromptView;
import com.quizlet.uicommon.ui.common.dialogs.ImageOverlayDialogFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements View.OnLongClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ b(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // android.view.View.OnLongClickListener
    public final boolean onLongClick(View view) {
        Object obj = this.c;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                c cVar = (c) obj;
                cVar.getAdapterPosition();
                if (cVar.b != null) {
                    ((com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a) obj2).getClass();
                    return false;
                }
                Intrinsics.m("folder");
                throw null;
            case 1:
                e eVar = (e) obj;
                eVar.getAdapterPosition();
                if (eVar.b != null) {
                    ((com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a) obj2).getClass();
                    return false;
                }
                Intrinsics.m("set");
                throw null;
            default:
                AbstractC1136h0 fragmentManager = ((WriteModeActivity) ((WriteModePromptView) obj2).V).getSupportFragmentManager();
                String str = ImageOverlayDialogFragment.x;
                String imagePath = (String) obj;
                Intrinsics.checkNotNullParameter(imagePath, "imagePath");
                Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
                com.quizlet.quizletandroid.managers.upgrade.a.i(imagePath, fragmentManager, null);
                return true;
        }
    }
}
