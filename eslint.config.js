import tseslint from 'typescript-eslint';
import hooks from 'eslint-plugin-react-hooks';
export default tseslint.config({ignores:['dist/**','node_modules/**']},...tseslint.configs.recommended,{files:['**/*.{ts,tsx}'],plugins:{'react-hooks':hooks},rules:{'react-hooks/rules-of-hooks':'error','react-hooks/exhaustive-deps':'warn','@typescript-eslint/no-explicit-any':'error'}});
