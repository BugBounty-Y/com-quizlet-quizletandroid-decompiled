package com.quizlet.baseui.base;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.viewbinding.a;
import com.quizlet.baseui.di.BaseDaggerFragment;
import com.quizlet.quizletandroid.ui.base.h;
import com.quizlet.quizletandroid.ui.group.GroupFragment;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public abstract class BaseFragment<T extends androidx.viewbinding.a> extends BaseDaggerFragment {
    public h b;
    public com.quizlet.baseui.interfaces.b c;
    public androidx.viewbinding.a d;

    public final void G(io.reactivex.rxjava3.disposables.b disposable) {
        Intrinsics.checkNotNullParameter(disposable, "subscription");
        h hVarL = L();
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        com.quizlet.baseui.managers.b bVar = hVarL.a;
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        Object value = bVar.d.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).b(disposable);
    }

    public final void H(io.reactivex.rxjava3.disposables.b disposable) {
        Intrinsics.checkNotNullParameter(disposable, "subscription");
        h hVarL = L();
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        Object value = hVarL.d.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).b(disposable);
    }

    public final void I(io.reactivex.rxjava3.disposables.b disposable) {
        Intrinsics.checkNotNullParameter(disposable, "subscription");
        h hVarL = L();
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        com.quizlet.baseui.managers.b bVar = hVarL.a;
        Intrinsics.checkNotNullParameter(disposable, "disposable");
        Object value = bVar.c.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        ((io.reactivex.rxjava3.disposables.a) value).b(disposable);
    }

    public final androidx.viewbinding.a J() {
        androidx.viewbinding.a aVar = this.d;
        if (aVar != null) {
            return aVar;
        }
        throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
    }

    public String K() {
        return null;
    }

    public final h L() {
        h hVar = this.b;
        if (hVar != null) {
            return hVar;
        }
        Intrinsics.m("mBaseFragmentDelegate");
        throw null;
    }

    public Integer M() {
        return null;
    }

    public abstract String N();

    public abstract androidx.viewbinding.a O(LayoutInflater layoutInflater, ViewGroup viewGroup);

    public boolean P() {
        return this instanceof GroupFragment;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        super.onAttach(context);
        if (context instanceof com.quizlet.baseui.interfaces.b) {
            this.c = (com.quizlet.baseui.interfaces.b) context;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onCreate(Bundle bundle) {
        timber.log.c.a.g("Creating fragment: %s", N());
        super.onCreate(bundle);
        h hVarL = L();
        Intrinsics.checkNotNullParameter(this, "fragment");
        getLifecycle().a(hVarL.a);
    }

    @Override // androidx.fragment.app.Fragment
    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        Intrinsics.checkNotNullParameter(menu, "menu");
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        Integer numM = M();
        if (numM != null) {
            inflater.inflate(numM.intValue(), menu);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        this.d = O(inflater, viewGroup);
        return J().getRoot();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        timber.log.c.a.g("Destroying fragment: %s", N());
        super.onDestroy();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        this.d = null;
    }

    @Override // androidx.fragment.app.Fragment
    public void onDetach() {
        super.onDetach();
        this.c = null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.fragment.app.Fragment
    public void onStart() {
        timber.log.a aVar = timber.log.c.a;
        aVar.g("Starting fragment: %s", N());
        super.onStart();
        if (this instanceof com.quizlet.baseui.interfaces.a) {
            com.quizlet.baseui.interfaces.b bVar = this.c;
            if (bVar != null) {
                ((b) bVar).j.add((com.quizlet.baseui.interfaces.a) this);
            }
            ((com.quizlet.baseui.interfaces.a) this).r();
        }
        h hVarL = L();
        String screenName = K();
        if (P()) {
            if (screenName == null) {
                throw new IllegalStateException("Override BaseFragment#getLoggingId if GA logging is needed");
            }
            com.quizlet.data.repository.user.a aVar2 = hVarL.c;
            Intrinsics.checkNotNullParameter(screenName, "screenName");
            ((com.quizlet.infra.legacysyncengine.managers.d) aVar2.b).a().i(new com.quizlet.quizletandroid.logging.ga.a(aVar2, screenName, null, null, null, null), new com.quizlet.billing.manager.d(aVar, 7));
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.fragment.app.Fragment
    public void onStop() {
        com.quizlet.baseui.interfaces.b bVar;
        timber.log.c.a.g("Stopping fragment: %s", N());
        if ((this instanceof com.quizlet.baseui.interfaces.a) && (bVar = this.c) != null) {
            ((b) bVar).j.remove((com.quizlet.baseui.interfaces.a) this);
        }
        super.onStop();
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        h hVarL = L();
        Intrinsics.checkNotNullParameter(this, "fragment");
        getViewLifecycleOwner().getLifecycle().a(hVarL);
    }
}
