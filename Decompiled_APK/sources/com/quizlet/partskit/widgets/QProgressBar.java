package com.quizlet.partskit.widgets;

import android.content.Context;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.widget.ProgressBar;
import androidx.swiperefreshlayout.widget.h;
import com.quizlet.features.achievements.achievement.f;

/* loaded from: classes3.dex */
public class QProgressBar extends ProgressBar {
    public h a;
    public boolean b;

    public QProgressBar(Context context) {
        super(context);
        this.b = true;
    }

    private void setAnimatedProgress(int i) {
        int progress = super.getProgress();
        if (progress != i) {
            h hVar = this.a;
            if (hVar == null || hVar.c != i) {
                if (hVar != null) {
                    hVar.cancel();
                }
                h hVar2 = new h(this, progress, i);
                this.a = hVar2;
                hVar2.setDuration(200L);
                this.a.setAnimationListener(new f(this, 1));
                startAnimation(this.a);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setUnscaledProgress(int i) {
        super.setProgress(i);
    }

    @Override // android.widget.ProgressBar
    public synchronized int getMax() {
        return super.getMax() / 1000;
    }

    @Override // android.widget.ProgressBar
    public synchronized int getProgress() {
        return super.getProgress() / 1000;
    }

    @Override // android.widget.ProgressBar, android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        this.b = false;
        super.onRestoreInstanceState(parcelable);
    }

    public void setImmediateProgress(int i) {
        h hVar = this.a;
        if (hVar != null) {
            hVar.cancel();
            this.a = null;
        }
        super.setProgress(i * 1000);
    }

    @Override // android.widget.ProgressBar
    public synchronized void setMax(int i) {
        super.setMax(i * 1000);
    }

    @Override // android.widget.ProgressBar
    public synchronized void setProgress(int i) {
        try {
            if (this.b) {
                setAnimatedProgress(i * 1000);
            } else {
                setAnimatedProgress(i);
            }
            this.b = true;
        } catch (Throwable th) {
            throw th;
        }
    }

    public QProgressBar(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.b = true;
    }
}
