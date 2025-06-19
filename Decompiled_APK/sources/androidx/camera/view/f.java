package androidx.camera.view;

import android.hardware.display.DisplayManager;
import android.view.Display;

/* loaded from: classes.dex */
public final class f implements DisplayManager.DisplayListener {
    public final /* synthetic */ PreviewView a;

    public f(PreviewView previewView) {
        this.a = previewView;
    }

    @Override // android.hardware.display.DisplayManager.DisplayListener
    public final void onDisplayAdded(int i) {
    }

    @Override // android.hardware.display.DisplayManager.DisplayListener
    public final void onDisplayChanged(int i) {
        PreviewView previewView = this.a;
        Display display = previewView.getDisplay();
        if (display == null || display.getDisplayId() != i) {
            return;
        }
        previewView.a();
    }

    @Override // android.hardware.display.DisplayManager.DisplayListener
    public final void onDisplayRemoved(int i) {
    }
}
