package com.amazon.aps.ads.util.adview;

import android.graphics.Rect;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import com.braze.ui.BrazeFeedFragment;
import com.google.android.material.search.SearchView;
import com.quizlet.quizletandroid.ui.FullScreenOverlayActivity;
import com.skydoves.balloon.Balloon;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class d implements View.OnTouchListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.View.OnTouchListener
    public final boolean onTouch(View view, MotionEvent event) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                int i = e.b;
                e this$0 = (e) obj;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                return this$0.detectAdClick(event);
            case 1:
                return ((BrazeFeedFragment) obj).lambda$onViewCreated$0(view, event);
            case 2:
                int i2 = SearchView.D;
                SearchView searchView = (SearchView) obj;
                if (searchView.g()) {
                    searchView.f();
                }
                return false;
            case 3:
                com.google.android.material.textfield.i iVar = (com.google.android.material.textfield.i) obj;
                iVar.getClass();
                if (event.getAction() == 1) {
                    long jCurrentTimeMillis = System.currentTimeMillis() - iVar.o;
                    if (jCurrentTimeMillis < 0 || jCurrentTimeMillis > 300) {
                        iVar.m = false;
                    }
                    iVar.u();
                    iVar.m = true;
                    iVar.o = System.currentTimeMillis();
                }
                return false;
            case 4:
                String str = FullScreenOverlayActivity.m;
                return ((GestureDetector) obj).onTouchEvent(event);
            case 5:
                Intrinsics.checkNotNullParameter(view, "<unused var>");
                Intrinsics.checkNotNullParameter(event, "event");
                com.quizlet.quizletandroid.ui.setcreation.viewholders.g gVar = (com.quizlet.quizletandroid.ui.setcreation.viewholders.g) obj;
                if (gVar.d().getVisibility() == 0) {
                    Rect rect = new Rect();
                    gVar.e.getGlobalVisibleRect(rect);
                    if (!rect.contains((int) event.getX(), (int) event.getY())) {
                        gVar.f();
                        return true;
                    }
                }
                return false;
            default:
                return Balloon.setOnBalloonOverlayTouchListener$lambda$49((Function2) obj, view, event);
        }
    }
}
