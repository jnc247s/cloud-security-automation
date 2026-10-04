import { useEffect, useRef, useState } from 'react';
import { readStamped } from './api';

export interface ReadProps { context: string; onError: (error: Error) => void }
export function useInvestigationRead<T>(path: string | null, valid: (v: unknown) => v is T, props: ReadProps, revision = 0) {
  const { context, onError } = props;
  const key = JSON.stringify([path, context, revision]);
  const [state, setState] = useState<{ key: string; data: { value: T; readAt: string | null } | null; error: string }>({ key, data: null, error: '' });
  const errors = useRef(onError);
  useEffect(() => { errors.current = onError; }, [onError]);
  useEffect(() => {
    const controller = new AbortController(); let active = true;
    setState({ key, data: null, error: '' });
    if (path) void readStamped(path, valid, controller.signal, context)
      .then(data => { if (active) setState({ key, data, error: '' }); })
      .catch((error: Error) => { if (active) { setState({ key, data: null, error: error.message }); errors.current(error); } });
    return () => { active = false; controller.abort(); };
  }, [path, valid, context, key]);
  return state.key === key ? state : { key, data: null, error: '' };
}
