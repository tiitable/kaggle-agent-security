# Notebooks

The Kaggle submission notebook lives here. Its job is small: write `attack.py`
to `/kaggle/working/` and launch the inference server the evaluator connects to.

## Structure of the submission notebook

```python
# 1. Path setup: add the competition dataset (kaggle_evaluation, aicomp_sdk) to sys.path
# 2. attack_code = '''<contents of ../attack.py>'''
#    open('/kaggle/working/attack.py','w').write(attack_code)
# 3. Launch the server:
#    import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server as s
#    s.JEDAttackInferenceServer().serve()
```

Keep the real attack logic in the top-level `attack.py` in this repo and paste it
into the `attack_code` string when submitting. That way the repo is the source of
truth and the notebook is just the delivery vehicle.

## Linking the repo to Kaggle

Kaggle notebooks support **File → Link to GitHub**, which lets you push the
notebook into this repo and pull updates back. Alternatively, keep `attack.py`
and the analysis here as the canonical copy, and treat the notebook purely as the
submission shell.
